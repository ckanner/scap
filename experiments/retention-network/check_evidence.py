"""Audit one complete real request-retirement experiment without mutating it.

Read the raw attempts, result receipts, application acknowledgements and fault
histories. No daemon is started, no request is repeated, and a failed sample
cannot be converted into a successful one by this checker.
"""

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import sys


NAMES = [
    "01-real-v3-hot-and-cold-producer",
    "02-wire-generations-cannot-form-quorum",
    "03-stop-upgrade-and-original-window-capacity",
    "04-explicit-receipts-and-ordered-retirement",
    "05-repeated-full-windows-with-offline-replica",
    "06-snapshot-installs-retirement-fences",
    "07-cold-ack-survives-legacy-hydration",
    "08-unknown-rotation-and-crash-recovery",
    "09-old-binary-rejects-v4-and-new-reopens",
]
PROFILE = {"databases": 32, "database_bytes": 262144, "requests_per_database": 128, "state_bytes": 8388608}
OLD_COMMIT = "b9f512819358494f178b01d7f1d960dff8222c1c"
SHA = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def u64(value, positive=False):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), f"not a canonical decimal: {value!r}")
    number = int(value)
    require(number <= 2**64 - 1 and (not positive or number > 0), "invalid u64")
    return number


def moment(value):
    require(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0, "invalid elapsed time")
    return value


def key(record):
    require(record["database"] in {"alpha", "beta"}, "unrecognised database")
    require(REQUEST_ID.fullmatch(record["request_id"]), "invalid request identity")
    u64(record["request_epoch"], True)
    return record["database"], record["request_epoch"], record["request_id"]


def sha(filename):
    digest = hashlib.sha256()
    with filename.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def object_sha(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def lines(filename):
    data = filename.read_text().splitlines()
    require(data and all(data), "empty record file: " + filename.name)
    return [json.loads(line) for line in data]


def unique(records, field, value):
    matches = [record for record in records if record.get(field) == value]
    require(len(matches) == 1, f"expected one {field}={value}, got {len(matches)}")
    return matches[0]


def local_position(record, node):
    require(record["authoritative"] is False and record["node_id"] == node, "local progress is not authoritative commit proof")
    status = record["status"]
    require(all(type(status[field]) is int and status[field] >= 0 for field in ("snapshot_index", "applied", "commit")), "invalid local progress")
    require(status["snapshot_index"] <= status["applied"] <= status["commit"] and status["is_voter"] is True, "local progress ordering differs")
    return status["applied"]


def request_http_attempts(record, http):
    """Select one logical call, not later explicit calls sharing its identity."""
    database, request_epoch, request_id = key(record)
    return sorted((raw for raw in http if raw["request_id"] == request_id and raw["request_epoch"] == request_epoch
                   and raw["route"].startswith("/db/" + database + "/")
                   and record["invoked_ms"] <= raw["invoked_ms"] <= raw["result_ms"] <= record["result_ms"]), key=lambda raw: raw["ordinal"])


def operation_http_attempts(record, raw):
    """Verify capability GETs separately from actual SQL/metadata operations.

    Epoch-scoped mutations probe the exact endpoint before their POST. That
    successful GET is not a replay, but it is still checked for the original
    deadline, ordering and node. Only an actual before-proposal NOT_LEADER
    response permits continuing to another endpoint after any attempt.
    """
    database, request_epoch, request_id = key(record)
    prefix = "/db/" + database + "/"
    kind = record["kind"]
    routes = {
        "write": ("POST", prefix + "v2/pipeline"),
        "read": ("POST", prefix + "v2/pipeline"),
        "lookup": ("POST", prefix + "v1/requests/" + request_id),
        "cancel": ("POST", prefix + "v1/requests/" + request_id),
        "acknowledge": ("POST", prefix + "v1/requests/" + request_id),
        "rotate": ("POST", prefix + "v1/request-epoch"),
        "status": ("GET", prefix + "v1/status"),
    }
    require(kind in routes, "unknown logical operation")
    needs_probe = request_epoch != "1" and kind in {"write", "cancel", "acknowledge", "rotate"}
    require(len({entry["deadline_unix_ms"] for entry in raw}) <= 1, "retry or capability probe reset the original deadline")
    require(all(left["result_ms"] <= right["invoked_ms"] for left, right in zip(raw, raw[1:])), "HTTP attempts overlap or run out of order")
    for entry in raw:
        require(entry["request_id"] == request_id and entry["request_epoch"] == request_epoch, "HTTP attempt changed the original identity")
        require(entry["mode"] == ("read" if kind == "read" else "write"), "HTTP attempt changed the original operation mode")

    def reroutable(entry):
        return entry["outcome"] == "response" and entry.get("code") == "NOT_LEADER"

    operations, index = [], 0
    while index < len(raw):
        if needs_probe:
            probe = raw[index]
            require((probe["method"], probe["route"]) == ("GET", prefix + "v1/status"), "scoped mutation lacks its endpoint capability probe")
            index += 1
            if not (probe["outcome"] == "response" and probe.get("status") == 200 and probe.get("code") is None):
                require(index == len(raw) or reroutable(probe), "request continued after failed capability probe")
                continue
            if index == len(raw):
                break  # Cancellation/deadline may stop the call before POST.
            require(raw[index]["node_id"] == probe["node_id"], "mutation used another endpoint's capability probe")
        operation = raw[index]
        require((operation["method"], operation["route"]) == routes[kind], "unexpected HTTP operation route or method")
        operations.append(operation)
        index += 1
        if index < len(raw):
            require(reroutable(operation), "request repeated after UNKNOWN/transport/late error")
    if record["outcome"] == "success":
        require(operations and operations[-1]["outcome"] == "response" and operations[-1].get("status") == 200
                and operations[-1].get("code") is None, "successful logical attempt has no real HTTP result")
    return operations


def histories(directory):
    require(sorted(filename.name for filename in directory.glob("*.history.jsonl")) == [name + ".history.jsonl" for name in NAMES], "history inventory differs")
    records, previous = [], 0
    for name in NAMES:
        content = (directory / (name + ".history.jsonl")).read_text().splitlines()
        require(content[-1] == "verification passed", "unfinished contract: " + name)
        current = [json.loads(line) for line in content[:-1]]
        require(current[0]["event"] == "contract_started" and current[0]["name"] == name, "missing start marker")
        require(current[-1]["event"] == "contract_completed" and current[-1]["name"] == name, "missing completion marker")
        for record in current:
            require(record["event"] != "contract_failed", "failed contract marked complete")
            require(moment(record["elapsed_ms"]) >= previous, "history time regressed")
            previous = record["elapsed_ms"]
        records.extend(current)
    return records


def audit(directory):
    require(directory.is_dir() and not (directory / "failure.json").exists(), "missing or failed run")
    manifest = json.loads((directory / "artifacts.json").read_text())
    expected_files = {name + ".history.jsonl" for name in NAMES} | {
        "binary.json", "s3-backend.json", "requests.jsonl", "http-attempts.jsonl", "write-results.jsonl",
        "application-acks.jsonl", "windows.jsonl", "summary.json",
    }
    require({entry["name"] for entry in manifest} == expected_files and len(manifest) == len(expected_files), "artifact manifest inventory differs")
    for entry in manifest:
        filename = directory / entry["name"]
        require(filename.stat().st_size == entry["bytes"] and sha(filename) == entry["sha256"], "artifact changed: " + entry["name"])

    observed = histories(directory)
    event = lambda name: unique(observed, "event", name)
    requests = lines(directory / "requests.jsonl")
    http = lines(directory / "http-attempts.jsonl")
    results = lines(directory / "write-results.jsonl")
    receipts = lines(directory / "application-acks.jsonl")
    windows = lines(directory / "windows.jsonl")
    summary = json.loads((directory / "summary.json").read_text())
    require(summary["completed"] == NAMES and summary["all_contracts_passed"] is True, "summary omitted a contract")
    require(summary["original_profile"] == PROFILE and summary["limits_increased"] is False, "original profile limits changed")
    require(summary["request_attempts"] == len(requests) and summary["http_attempts"] == len(http), "attempt denominator differs")
    failed = [record for record in requests if record["outcome"] != "success"]
    require(failed == summary["unsuccessful_attempts"], "failed/UNKNOWN samples were discarded")
    require(all(record["outcome"] == "service_error" for record in failed), "unexpected harness failure")
    for records in (requests, http):
        require(sorted(record["ordinal"] for record in records) == list(range(len(records))), "attempt ordinal gap or duplicate")
        for record in records:
            require(moment(record["invoked_ms"]) <= moment(record["result_ms"]), "request interval reversed")
    by_http = {record["ordinal"]: record for record in http}
    for record in http:
        require(record["node_id"] in {1, 2, 3}, "HTTP attempt left the configured replica set")
        require(record["method"] in {"GET", "POST"}, "unexpected HTTP mutation")
        if record["request_id"] is not None:
            require(REQUEST_ID.fullmatch(record["request_id"]), "malformed HTTP request ID")
            u64(record["request_epoch"], True)
            u64(record["deadline_unix_ms"], True)
        require(record["outcome"] in {"response", "response_lost", "transport_error"}, "unknown HTTP observation")

    operation_attempts, claimed_http = {}, Counter()
    for record in requests:
        raw = request_http_attempts(record, http)
        operation_attempts[record["ordinal"]] = operation_http_attempts(record, raw)
        claimed_http.update(entry["ordinal"] for entry in raw)
        if "statements_sha256" in record:
            require(SHA.fullmatch(record["statements_sha256"]), "missing original statement fingerprint witness")
    require(claimed_http == Counter(entry["ordinal"] for entry in http if entry["request_id"] is not None),
            "tenant HTTP attempt was unaccounted for or attributed to multiple logical calls")

    committed = {key(record): record for record in results}
    require(len(committed) == len(results), "duplicate retained result identity")
    cancelled = {key(record): record for record in requests if record["kind"] == "cancel" and record["outcome"] == "success"}
    require(len(cancelled) == 3 and all(record["observed_state"] == "cancelled" for record in cancelled.values()), "original cancellation fence denominator differs")
    require(not set(committed) & set(cancelled), "one request both committed and cancelled")
    retained = set(committed) | set(cancelled)
    for identity, result in committed.items():
        operations = [record for record in requests if key(record) == identity and record["kind"] == "write" and record["label"] == result["label"]]
        require(len(operations) == 1, "retained result lacks one original SQL attempt")
        operation = operations[0]
        require(operation["statements_sha256"] == result["statements_sha256"], "statement changed across retained receipt")
        if result["observed_via"] == "successful_sql_response":
            require(operation["outcome"] == "success", "unsuccessful SQL was counted as a successful response")
        else:
            require(result["observed_via"] == "lookup_after_response_loss" and operation["code"] == "COMMIT_UNKNOWN", "unknown write was relabelled successful")
        terminal = [record for record in requests if key(record) == identity and record["kind"] == "lookup" and record["outcome"] == "success" and record.get("observed_state") == "committed"]
        require(terminal and all(record["results_sha256"] == object_sha([result["result"]]) for record in terminal), "retained SQL result changed across lookup/recovery")
    require(summary["successful_sql_responses"] == sum(record["observed_via"] == "successful_sql_response" for record in results), "SQL response denominator differs")
    require(summary["committed_unknown_results_resolved_without_sql_replay"] == sum(record["observed_via"] == "lookup_after_response_loss" for record in results) == 1, "missing single lost-write resolution")

    acknowledged = {key(record): record for record in receipts}
    require(len(acknowledged) == len(receipts) == summary["application_acknowledgements"], "application receipt duplicate or denominator mismatch")
    successful_acks = [record for record in requests if record["kind"] == "acknowledge" and record["outcome"] == "success"]
    require(len(successful_acks) == len(receipts), "receipt lacks a successful explicit ACK")
    for identity, receipt in acknowledged.items():
        require(identity in retained, "ACK was not tied to an actual terminal request")
        matches = [record for record in successful_acks if key(record) == identity and record["label"] == receipt["label"]]
        require(len(matches) == 1, "ACK identity/label differs")
        ack = matches[0]
        proof = [record for record in requests if key(record) == identity and record["kind"] == "lookup" and record["outcome"] == "success"
                 and record.get("observed_state") == receipt["state"] and record["result_ms"] <= ack["invoked_ms"]]
        require(proof, "application acknowledged without a prior observed terminal")
        terminal = max(proof, key=lambda record: record["result_ms"])
        require(terminal["acknowledged"] is False, "receipt was generated by an implicit or earlier ACK")
        if receipt["state"] == "committed":
            require(receipt["sequence"] == terminal["sequence"] and receipt["result_sha256"] == terminal["results_sha256"], "committed receipt proof mismatch")
            u64(receipt["sequence"], True)
        else:
            require(receipt["state"] == "cancelled" and receipt["position"] == terminal["position"] and receipt["position"] is not None, "cancelled receipt has no exact position")
            for field in ("term", "index"):
                u64(receipt["position"][field], True)

    expected_windows = [("alpha", "1", "2", 128), ("alpha", "2", "3", 128), ("alpha", "3", "4", 128), ("beta", "1", "2", 3), ("alpha", "4", "5", 1)]
    require([(entry["database"], entry["from_epoch"], entry["to_epoch"], u64(entry["retained_before"])) for entry in windows] == expected_windows, "request-window sequence or size differs")
    for window in windows:
        database, original_epoch = window["database"], window["from_epoch"]
        identities = {identity for identity in retained if identity[:2] == (database, original_epoch)}
        require(len(identities) == u64(window["retained_before"]) and identities <= acknowledged.keys(), "rotation discarded unacknowledged/uncounted outcomes")
        require(u64(window["to_epoch"]) == u64(original_epoch) + 1 and u64(window["unacknowledged_before"]) == u64(window["retained_after"]) == 0, "rotation counters differ")
        require(window["revision_before"] == window["revision_after"] == window["retired_revision"], "logical retirement changed physical head revision")
        require(window["sql_before"] == window["sql_after"] and window["archive_cleared"] is True, "rotation changed SQL or retained the old live archive reference")
        require(SHA.fullmatch(window["sql_before"]["sha256"]) and window["sql_before"]["rows"] > 0, "no complete SQL state digest")
        rotation = [record for record in requests if record["kind"] == "rotate" and record["request_id"] == window["request_id"]]
        require(len(rotation) == 1 and rotation[0]["request_epoch"] == original_epoch, "rotation changed its original generation")
        require(rotation[0]["outcome"] == ("service_error" if window["lost_response"] else "success"), "rotation outcome relabelled")
        for identity in identities:
            require(next(record for record in successful_acks if key(record) == identity)["result_ms"] <= rotation[0]["invoked_ms"], "rotation preceded application processing")
        for suffix, field in (("_before", "retained_before"), ("_after", "retained_after")):
            view = unique(requests, "label", rotation[0]["label"] + suffix)["metadata"]
            require(view["retainedRequests"] == window[field], "window counter not backed by fresh metadata")
    require(summary["full_alpha_windows"] == 3 and u64(summary["total_retired_records"]) == sum(u64(window["retained_before"]) for window in windows) == 388, "retirement denominator differs")
    require(summary["final_request_epochs"] == {"alpha": "5", "beta": "2"}, "final namespace differs")
    pending = {key(record): record for record in summary["current_retained_results"]}
    require(set(pending) == retained - acknowledged.keys() and len(pending) == 2 and all(record["acknowledged"] is False for record in pending.values()), "current unacknowledged results were lost or auto-released")
    reused = [identity for identity in retained if identity[0] == "alpha" and any(other[0] == identity[0] and other[2] == identity[2] and other[1] != identity[1] for other in retained)]
    require(len(reused) == 2 and {identity[1] for identity in reused} == {"1", "2"}, "same request ID was not reused under a distinct new namespace")

    expected_errors = {
        "wrong_terminal_receipt_rejected": "RESOLVE_REJECTED", "different_principal_cannot_ack": "RESOLVE_REJECTED",
        "same_principal_read_only_cannot_borrow_write": "UNAUTHORIZED", "ordinary_writer_cannot_rotate": "UNAUTHORIZED",
        "unacknowledged_window_cannot_rotate": "RETIREMENT_REJECTED", "unprocessed_unknown_commit_blocks_rotation": "RETIREMENT_REJECTED",
        "retired_execute_rejected": "REQUEST_RETIRED", "retired_cancellation_rejected": "REQUEST_RETIRED",
        "retired_acknowledgement_rejected": "REQUEST_RETIRED", "cold_rotation_requires_physical_materialization": "RETIREMENT_REJECTED",
        "committed_response_deliberately_lost": "COMMIT_UNKNOWN", "129th_record_rejected_without_retry": "COMMIT_UNKNOWN",
        "rotation_response_deliberately_lost": "COMMIT_UNKNOWN",
    }
    for label, code in expected_errors.items():
        logical = unique(failed, "label", label)
        require(logical["code"] == code and len(operation_attempts[logical["ordinal"]]) == 1, "negative mutation missing real one-attempt rejection: " + label)
    capacity = event("original_request_capacity_preserved")
    require(capacity["limit"] == u64(capacity["observed_records"]) == 128 and capacity["overflow_posts"] == 1, "128/129 capacity boundary was not observed")
    blocked = unique(requests, "label", "unknown_result_remains_unacknowledged")["metadata"]
    require(u64(blocked["retainedRequests"]) == 128 and u64(blocked["unacknowledgedRequests"]) == 1, "lost write was not the last pending application receipt")
    require(sum(record.get("observed_state") == "retired" and record["label"] == "every_original_identity_is_retired" for record in requests) == 128, "not every original identity was checked after rotation")
    injected = [record for record in http if record.get("injected_response_loss")]
    require(len(injected) == 2 and all(record["outcome"] == "response_lost" and record["status"] == 200 and record["code"] is None for record in injected), "response loss was not injected after two complete successful server replies")
    for record in injected:
        mutations = [entry for entry in http if entry["request_id"] == record["request_id"] and entry["request_epoch"] == record["request_epoch"] and entry["route"] == record["route"] and entry["method"] == "POST"]
        require(mutations == [record], "lost mutation was blindly replayed")
    require(summary["lost_rotation"]["mutation_posts"] == 1 and by_http[summary["lost_rotation"]["http_ordinal"]] in injected, "lost rotation receipt does not identify its exact POST")

    legacy = event("real_v3_fixture_created")
    require(legacy["source_commit"] == OLD_COMMIT and legacy["profile_limits"] == PROFILE and legacy["synthetic_old_state"] is False, "legacy producer was not pinned")
    require(legacy["beta"]["cold"] is True and legacy["archives"] and all(entry["format_version"] == 3 for entry in legacy["archives"]), "old V3 archive bytes missing")
    mixed = event("wire_generations_fenced")
    upgraded = mixed["upgraded_node_id"]
    require(mixed["old_peer_envelope_version"] == 2 and mixed["new_peer_envelope_version"] == 3 and mixed["peer_proxies_blocked"] is False, "wire isolation was simulated by blocking the network")
    require(local_position(mixed["isolated_new"], upgraded) < mixed["old_quorum_witness"]["applied"] and mixed["old_quorum_witness"]["leader"] != upgraded, "old quorum witness did not exceed new replica prefix")
    for field in ("rejected_read", "rejected_write"):
        rejection = mixed[field]
        raw = by_http[rejection["http_ordinal"]]
        require(raw["node_id"] == upgraded and raw["outcome"] == "response" and raw["code"] in {"NOT_LEADER", "COMMIT_UNKNOWN", "EXPIRED"}, "mixed-version probe lacks a service response")
        require(rejection["posts"] == 1 and rejection["actual_service_response"] is True and rejection["original_server_deadline_ms"] == 2500 and rejection["response_drain_allowance_ms"] == 1500, "mixed-version deadline or attempt budget differs")
    require(("alpha", "1", mixed["rejected_write"]["request_id"]) in cancelled, "uncertain mixed write was not ordered-cancelled under its original identity")
    require(unique(requests, "label", "old_quorum_still_commits")["outcome"] == "success", "old quorum stopped accepting writes")
    stopped = event("all_old_and_new_processes_stopped")
    require(len(stopped["replicas"]) == 3 and all(record["exit"] == {"code": 0, "signal": None} for record in stopped["replicas"]), "not all versions stopped before full upgrade")
    upgrade = event("same_legacy_directories_activated_v4")
    require(local_position(upgrade["lagging_replica_caught_up"], upgraded) >= upgrade["witnessed_old_prefix"] == mixed["old_quorum_witness"]["applied"], "mixed replica never caught up on its original disk")
    require(upgrade["original_beta"]["cold"] is True and upgrade["original_alpha"]["requestEpoch"] == "1", "activation lost cold state or changed original namespace")

    snapshot = event("retirement_snapshot_install_verified")
    lagger = snapshot["lagging_node_id"]
    old_applied = local_position(snapshot["before"], lagger)
    require(len(snapshot["available_sources"]) == 2 and {source["node_id"] for source in snapshot["available_sources"]} == {1, 2, 3} - {lagger}, "snapshot sources differ")
    for source in snapshot["available_sources"]:
        local_position(source, source["node_id"])
        require(source["status"]["snapshot_index"] > old_applied, "source had not purged beyond lagging applied prefix")
    require(local_position(snapshot["after"], lagger) >= snapshot["witnessed_prefix"] and snapshot["after"]["status"]["snapshot_index"] >= min(source["status"]["snapshot_index"] for source in snapshot["available_sources"]), "same-disk replica did not install the advanced snapshot")
    require(snapshot["new_directory_created"] is False and snapshot["local_status_is_commit_proof"] is False and snapshot["beta_cold"]["cold"] is True, "snapshot check recreated a disk or woke the legacy archive early")

    blackhole = event("legacy_archive_tcp_blackhole_observed")
    require(blackhole["blocked_connections_after"] > blackhole["blocked_connections_before"] and blackhole["hot_alpha_read_succeeded"] is True, "real S3 TCP blackhole not observed")
    require(blackhole["beta"]["cold"] is True and blackhole["beta"]["unacknowledgedRequests"] == "0", "failed wake changed cold application receipts")
    require(unique(failed, "label", "legacy_archive_blackhole")["kind"] == "read", "cold wake failure sample missing")
    archive = event("cold_metadata_and_archive_generations_preserved")
    require(archive["cold_ack"]["cold"] is True and archive["cold_ack"]["unacknowledgedRequests"] == "0" and archive["old_archives"] == legacy["archives"], "ACK did not occur on the original cold archive")
    require(any(entry["format_version"] == 4 for entry in archive["new_archives"]), "no new V4 archive object")
    require({entry["sha256"] for entry in legacy["archives"]} <= {entry["sha256"] for entry in archive["new_archives"]}, "old immutable archive disappeared")
    for entry in legacy["archives"] + archive["new_archives"]:
        require(entry["sha256"] == entry["key"].rsplit("/", 1)[1] and entry["bytes"] > 9, "archive content address differs")

    killed = event("three_replicas_sigkilled")
    require(len(killed["replicas"]) == 3 and all(record["exit"]["signal"] == "SIGKILL" for record in killed["replicas"]), "whole-group failure was not SIGKILL")
    crash = event("unknown_rotation_and_crashes_preserve_fences")
    require(crash["leader_exit"]["signal"] == "SIGKILL" and crash["acknowledged_sql_lost"] == 0 and crash["original_unknown_sql_replayed"] is False, "leader crash witness differs")
    old_workers = {record["worker_instance"] for record in killed["prior_writer_files"]}
    require(len(crash["recovered_files"]) >= 2 and all(record["worker_instance"] not in old_workers and 0 <= record["main_file_bytes"] <= PROFILE["database_bytes"] for record in crash["recovered_files"]), "fresh recovered writer directories missing")
    downgrade = event("v3_downgrade_rejected_and_v4_state_reopened")
    require(downgrade["sql"] == crash["sql"] and downgrade["source_inputs_unchanged"] is True, "downgrade/reopen changed SQL or an input")
    require(len(downgrade["rejections"]) == summary["downgrade_rejected_nodes"] == 3 and downgrade["all_new_daemons_stopped_before_old_opens"] is True and downgrade["no_database_reinitialization"] is True, "downgrade setup differs")
    for record in downgrade["local_applied_before_stop"]:
        require(local_position(record, record["node_id"]) >= downgrade["committed_before_stop"], "old daemon tested against a legacy lagging disk")
    for rejection in downgrade["rejections"]:
        require(rejection["reason"] == "STORE_APPLICATION" and type(rejection["exit"]["code"]) is int and rejection["exit"]["code"] != 0 and rejection["exit"]["signal"] is None and rejection["old_compatible_configuration"] is True and rejection["initialize_flag_used"] is False, "downgrade rejected for an unrelated configuration/lock reason")

    binaries = json.loads((directory / "binary.json").read_text())
    require(binaries["old"]["source_commit"] == OLD_COMMIT and binaries["old"]["selected_build_receipt_sha256"] == binaries["old"]["sha256"] == legacy["producer_sha256"], "old source/build receipt differs")
    require(binaries["old"]["sha256"] != binaries["current"]["sha256"], "both versions used the same binary")
    for entry in [binaries["old"], binaries["current"], *binaries["harness"]]:
        filename = Path(entry["path"])
        require(SHA.fullmatch(entry["sha256"]) and filename.stat().st_size == entry["bytes"] and sha(filename) == entry["sha256"], "input identity changed: " + str(filename))
    require(summary["effective_voters"] == [1, 2, 3] and summary["membership_changes_submitted"] == 0, "retirement changed membership")
    require(summary["acknowledged_sql_lost"] == 0 and summary["production_slo_passed"] is False and summary["private_fixture_data_exported"] is False, "evidence overstated durability/SLO/privacy scope")
    return {
        "passed": True, "contracts": len(NAMES), "request_attempts": len(requests), "http_attempts": len(http),
        "unsuccessful_attempts": failed, "successful_sql_responses": summary["successful_sql_responses"],
        "committed_unknown_results_resolved_without_sql_replay": 1, "explicit_application_acknowledgements": len(receipts),
        "retired_request_identities": 388, "current_unacknowledged_results": 2, "full_alpha_windows": 3,
        "fixed_request_window": 128, "final_request_epochs": summary["final_request_epochs"],
        "binary_and_harness_identities_verified": True, "production_source_identity_requires_build_receipt": True,
        "production_slo_passed": False,
    }


if __name__ == "__main__":
    require(len(sys.argv) == 2, "usage: check_evidence.py /absolute/completed/evidence")
    print(json.dumps(audit(Path(sys.argv[1])), indent=2))
