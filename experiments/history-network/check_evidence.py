"""Read-only integrity checks for a completed real history upgrade experiment.

This checks raw denominators, observed counters and identities; it never runs a
daemon, retries a request, or upgrades a failure to a successful observation.
"""

import hashlib
import json
import math
from pathlib import Path
import re
import sys


NAMES = [
    "01-old-v2-hot-and-cold",
    "02-mixed-versions-cannot-form-quorum",
    "03-stop-upgrade-preserves-history",
    "04-overwrite-exceeds-original-history-budget",
    "05-old-s3-archive-hydrates-with-new-fence",
    "06-new-v4-archive-roundtrip",
    "07-sigkill-recovers-from-base-and-tail",
    "08-old-binary-rejects-v4-storage",
    "09-new-binary-reopens-after-rejected-downgrade",
]
PROFILE = {
    "databases": 32,
    "database_bytes": 256 * 1024,
    "requests_per_database": 128,
    "state_bytes": 8 * 1024 * 1024,
    "transaction_bytes": 300 * 1024,
    "tail_entries_trigger": 8,
    "tail_bytes_trigger": 1_228_800,
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def u64(value):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), f"not canonical decimal: {value!r}")
    number = int(value)
    require(number <= 2**64 - 1, "u64 overflow")
    return number


def lines(path):
    data = path.read_text().splitlines()
    require(data and all(data), f"empty/missing record: {path.name}")
    return [json.loads(line) for line in data]


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def events(directory):
    require(sorted(path.name for path in directory.glob("*.history.jsonl")) == [name + ".history.jsonl" for name in NAMES], "history inventory differs")
    result, previous = {}, 0
    for name in NAMES:
        content = (directory / (name + ".history.jsonl")).read_text().splitlines()
        require(content[-1] == "verification passed", f"unfinished history: {name}")
        records = [json.loads(line) for line in content[:-1]]
        require(records[0]["event"] == "contract_started" and records[0]["name"] == name, "incorrect start marker")
        require(records[-1]["event"] == "contract_completed" and records[-1]["name"] == name, "incorrect completion marker")
        require(not any(record["event"] == "contract_failed" for record in records), "failed history was marked complete")
        for record in records:
            require(isinstance(record["elapsed_ms"], (int, float)) and not isinstance(record["elapsed_ms"], bool) and math.isfinite(record["elapsed_ms"]) and record["elapsed_ms"] >= previous, "invalid/reversed history timestamp")
            previous = record["elapsed_ms"]
            result.setdefault(record["event"], []).append(record)
    return result


def one(observed, event):
    require(len(observed.get(event, [])) == 1, "missing/duplicated " + event)
    return observed[event][0]


def local_position(observation, node):
    require(observation["authoritative"] is False and observation["node_id"] == node, "local status was misrepresented as commit confirmation")
    status = observation["status"]
    require(status["is_voter"] is True, "original voter identity changed")
    for field in ("applied", "commit", "snapshot_index"):
        require(isinstance(status[field], int) and not isinstance(status[field], bool) and 0 <= status[field] <= 2**53 - 1, "invalid local status counter")
    require(status["snapshot_index"] <= status["applied"] <= status["commit"], "inconsistent local durable position")
    return status["applied"]


def legacy_cancelled(outcome):
    """The old service has no terminal position or acknowledgement metadata."""
    require(isinstance(outcome, dict) and outcome.get("state") == "cancelled", "mixed request was silently treated as cancelled")
    require(set(outcome) in ({"state"}, {"state", "position", "acknowledged"}), "unexpected legacy cancellation fields")
    if "position" in outcome:
        require(outcome["position"] is None and outcome["acknowledged"] is False, "legacy cancellation acquired a fabricated position or acknowledgement")


def audit(directory):
    summary = json.loads((directory / "summary.json").read_text())
    require(summary["completed"] == NAMES and summary["all_contracts_passed"] is True, "incomplete run")
    require(summary["production_slo_passed"] is False and summary["private_fixture_data_exported"] is False, "incorrect evidence scope")
    require(summary["profile_limits"] == PROFILE, "original production profile was changed")
    require(summary["original_results_lost"] == 0 and summary["current_sql_state_equal"] is True, "lost results/state")
    observed = events(directory)
    requests = lines(directory / "requests.jsonl")
    http = lines(directory / "http-attempts.jsonl")
    acks = lines(directory / "acknowledgements.jsonl")
    overwrites = lines(directory / "overwrites.jsonl")
    for records in (requests, http):
        require(sorted(record["ordinal"] for record in records) == list(range(len(records))), "missing/duplicate attempt ordinal")
        for record in records:
            require(all(isinstance(record[field], (int, float)) and not isinstance(record[field], bool) and math.isfinite(record[field]) for field in ("invoked_ms", "result_ms")), "invalid attempt time")
            require(0 <= record["invoked_ms"] <= record["result_ms"], "reversed attempt times")
    by_request_ordinal = {record["ordinal"]: record for record in requests}
    require(len(requests) == summary["request_attempts"] and len(http) == summary["http_attempts"], "attempt denominator mismatch")
    failed = [record for record in requests if record["outcome"] != "success"]
    require(sorted(failed, key=lambda record: record["ordinal"]) == sorted(summary["unsuccessful_attempts"], key=lambda record: record["ordinal"]), "failures were dropped from summary")
    require({record["label"] for record in failed} == {
        "new_version_cannot_read_from_old_quorum",
        "new_version_write_sent_once",
        "one_old_and_one_new_cannot_serve_strong_read",
        "original_fence_after_many_bases_late_attempt",
        "wrong_tenant_cannot_wake_old_archive",
        "real_old_archive_blackhole",
        "new_fence_survives_old_archive_hydrate_late_attempt",
    }, "unexpected missing/additional failed request")
    require(len(failed) == 7, "failed-request denominator changed")

    acknowledged = {(record["database"], record["request_id"]): record for record in acks}
    require(len(acknowledged) == len(acks) == summary["acknowledged_writes"] == 80, "ACK inventory changed")
    successful_writes = {(record["database"], record["request_id"]) for record in requests if record["kind"] == "write" and record["outcome"] == "success"}
    require(successful_writes == set(acknowledged), "successful write missing its result witness")
    by_database = {database: sum(record["database"] == database for record in acks) for database in ("alpha", "beta")}
    require(by_database == summary["acknowledgements_by_database"] == {"alpha": 69, "beta": 11}, "per-database ACK denominator differs")
    cancels = [record for record in requests if record["kind"] == "cancel"]
    require(len(cancels) == summary["cancellation_fences"] == 5 and all(record.get("observed_state") == "cancelled" for record in cancels), "cancel fence inventory differs")
    cancel_ids = {(record["database"], record["request_id"]) for record in cancels}
    require(len(cancel_ids) == 5 and not cancel_ids.intersection(acknowledged), "cancel/ACK identity collision")
    identities = {database: sum(key[0] == database for key in set(acknowledged).union(cancel_ids)) for database in ("alpha", "beta")}
    require(identities == summary["retained_request_identities"] and all(value < 128 for value in identities.values()), "retained identity budget differs")
    final_lookups = [record for record in requests if record["kind"] == "lookup" and record["label"] == "after_rejected_downgrade"]
    require(len(final_lookups) == 85, "final ACK/cancel verification denominator differs")
    require({(record["database"], record["request_id"]) for record in final_lookups} == set(acknowledged).union(cancel_ids), "final outcome verification omitted an identity")
    for record in final_lookups:
        key = (record["database"], record["request_id"])
        require(record["outcome"] == "success", "final lookup failed")
        if key in cancel_ids:
            require(record["observed_state"] == "cancelled", "cancel reverted during recovery")
        else:
            require(record["observed_state"] == "committed" and u64(record["sequence"]) > 0, "ACK no longer committed")
            expected = hashlib.sha256(json.dumps([acknowledged[key]["result"]], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
            require(record["results_sha256"] == expected, "original returned result changed")

    # A transport failure, deadline or UNKNOWN cannot trigger another SQL POST.
    # The production SDK's explicit before-proposal NOT_LEADER is the only
    # permitted continuation for an identical SQL invocation.
    sql_posts = {}
    for record in sorted(http, key=lambda value: value["ordinal"]):
        if record["method"] == "POST" and record["route"].endswith("/v2/pipeline") and record["mode"] == "write":
            sql_posts.setdefault(record["request_id"], []).append(record)
    for request_id, posts in sql_posts.items():
        require(all(record["outcome"] == "response" and record.get("code") == "NOT_LEADER" for record in posts[:-1]), "SQL was resent after an uncertain response: " + request_id)
        require(len({u64(record["deadline_unix_ms"]) for record in posts}) == 1, "SQL routing continuation changed the original deadline: " + request_id)
    write_ids = {record["request_id"] for record in requests if record["kind"] == "write"}
    require(set(sql_posts) == write_ids, "actual SQL POST inventory differs from logical invocations")
    for label in ("original_fence_after_many_bases", "new_fence_survives_old_archive_hydrate"):
        late = [record for record in failed if record["label"] == label + "_late_attempt"]
        require(len(late) == 1 and late[0]["kind"] == "write", "missing exact late-cancel SQL attempt")
        late = late[0]
        final = sql_posts[late["request_id"]][-1]
        require(final["outcome"] == "response" and final.get("code") == late["code"] == "COMMIT_UNKNOWN", "late-cancel rejection was replaced by a routing or transport failure")
        require(late["invoked_ms"] <= final["invoked_ms"] <= final["result_ms"] <= late["result_ms"], "late-cancel response is outside the original invocation")
        lookup = by_request_ordinal.get(late["ordinal"] + 1, {})
        require(lookup.get("kind") == "lookup" and lookup["label"] == label and lookup["database"] == late["database"] and lookup["request_id"] == late["request_id"] and lookup["outcome"] == "success" and lookup["observed_state"] == "cancelled" and lookup["invoked_ms"] >= late["result_ms"], "late-cancel rejection has no immediate exact ordered-outcome verification")

    mixed_start = one(observed, "mixed_version_started")
    mixed = one(observed, "mixed_version_fence_verified")
    upgraded = mixed["upgraded_node_id"]
    require(upgraded == mixed_start["upgraded_node_id"] and upgraded in (1, 2, 3), "mixed upgraded identity differs")
    require(mixed_start["old_peer_envelope_version"] == summary["old_peer_envelope_version"] == 1 and mixed_start["new_peer_envelope_version"] == summary["new_peer_envelope_version"] == 3, "wrong version fence")
    require(mixed_start["initialize_flag_used"] is False and mixed["lagging_directory_retained"] is True, "mixed replica was rebuilt instead of reopened")
    require(mixed_start["peer_proxies_blocked"] is False and mixed["peer_proxies_blocked"] is False, "a network partition was substituted for version rejection")
    configuration = {"voters": [1, 2, 3], "learners": [], "voters_outgoing": [], "learners_next": [], "auto_leave": False}
    for membership in (mixed_start["original_membership"], mixed["old_quorum"], mixed["source_before_full_upgrade"], one(observed, "new_binary_reopened_without_ack_loss")["final_membership"]):
        require(membership["conf_state"] == configuration, "effective membership changed")
    require(summary["effective_voters"] == [1, 2, 3] and summary["membership_changes_submitted"] == mixed["membership_changes_submitted"] == 0, "membership change included in fixed-voter upgrade evidence")
    require(summary["dynamic_peer_policy_for_existing_read_only_management"] is True and summary["local_status_is_commit_confirmation"] is False and summary["mixed_versions_rejected"] is True, "management observation scope differs")
    require(not any(record["method"] != "GET" and record["route"].startswith("/v1/admin/") for record in http), "management mutation was sent")
    original_status = mixed_start["original_local_status"]
    require(len(original_status) == 3 and {record["node_id"] for record in original_status} == {1, 2, 3}, "original caught-up replica inventory differs")
    require(all(local_position(record, record["node_id"]) >= mixed_start["original_membership"]["applied"] for record in original_status), "mixed prefix was not present on the old replicas")
    prefix = local_position(mixed_start["new_prefix"], upgraded)
    require(prefix == local_position(mixed["prefix"], upgraded) == local_position(mixed["frozen"], upgraded), "new replica applied old-version suffix while isolated")
    require(prefix < mixed["old_quorum"]["applied"] <= mixed["source_before_full_upgrade"]["applied"], "no real committed suffix accumulated after mixed upgrade")
    live_nodes = mixed["mixed_minority_live_nodes"]
    require(len(set(live_nodes)) == 2 and upgraded in live_nodes and set(live_nodes).union({mixed["stopped_old_node_id"]}) == {1, 2, 3}, "mixed minority process inventory differs")
    require({record["node_id"] for record in mixed["mixed_minority_local_status"]} == set(live_nodes), "both mixed-minority processes were not observed alive")
    for record in mixed["mixed_minority_local_status"]:
        local_position(record, record["node_id"])
    for exit_record in (mixed_start["replaced_old_exit"], mixed["stopped_old_exit"], mixed["new_exit"]):
        require(exit_record == {"code": 0, "signal": None}, "mixed transition did not fully stop the previous owner of a replica directory")
    require(mixed_start["old_stopped_ms"] <= mixed_start["new_live_ms"] <= mixed["old_minority_started_ms"] <= mixed["new_stopped_ms"] <= mixed["old_quorum_restored_ms"], "mixed process lifecycle ordering differs")
    by_http_ordinal = {record["ordinal"]: record for record in http}
    preparation_start = one(observed, "old_quorum_recovery_preparation_started")
    preparation = one(observed, "old_quorum_recovery_prepared")
    require(preparation_start["nodes"] == [node for node in live_nodes if node != upgraded] + [mixed["stopped_old_node_id"]], "quorum preparation used the new-version replica")
    require(preparation["original_budget_ms"] == preparation_start["original_budget_ms"] == 30_000 and preparation["started_ms"] == preparation_start["started_ms"] and preparation["deadline_ms"] == preparation_start["deadline_ms"] == preparation["started_ms"] + 30_000, "quorum preparation reset its original recovery deadline")
    require(preparation_start["sql_submitted"] is False and preparation["sql_submitted"] is False and mixed["new_stopped_ms"] <= preparation["started_ms"] <= preparation["completed_ms"] < preparation["deadline_ms"], "invalid quorum preparation interval")
    confirmations = preparation["confirmations"]
    require(len(confirmations) == 2, "quorum recovery needs two fresh read confirmations")
    for confirmation in confirmations:
        raw = by_http_ordinal[confirmation["http_ordinal"]]
        view = confirmation["membership"]
        require(raw["method"] == "GET" and raw["route"] == "/v1/admin/membership" and raw["node_id"] == confirmation["node_id"] == view["leader_id"] == view["leader"] and raw["outcome"] == "response" and raw["status"] == 200, "quorum confirmation is not a successful fresh membership response")
        require(preparation["started_ms"] <= raw["invoked_ms"] <= raw["result_ms"] <= preparation["completed_ms"] and view["conf_state"] == configuration, "quorum preparation confirmation is out of scope")
    first, second = confirmations
    require(first["node_id"] == second["node_id"] and first["membership"]["term"] == second["membership"]["term"] and first["membership"]["applied"] <= second["membership"]["applied"], "quorum preparation did not confirm the same leader and term with monotonic applied")
    ready = by_http_ordinal[preparation["readiness"]["http_ordinal"]]
    require(ready["method"] == "GET" and ready["route"] == "/readyz" and ready["node_id"] == preparation["readiness"]["node_id"] == first["node_id"] and ready["outcome"] == "response" and ready["status"] == 200 and first["http_ordinal"] < ready["ordinal"] < second["http_ordinal"], "readiness observation was not bracketed by fresh quorum confirmations")
    require(not any(record["method"] != "GET" for record in http if preparation["started_ms"] <= record["invoked_ms"] <= preparation["completed_ms"]), "quorum preparation submitted a mutation or SQL POST")
    negative_labels = (("rejected_new_read", "new_version_cannot_read_from_old_quorum", "read"), ("rejected_new_write", "new_version_write_sent_once", "write"), ("rejected_mixed_minority_read", "one_old_and_one_new_cannot_serve_strong_read", "read"))
    for field, label, mode in negative_labels:
        rejection = mixed[field]
        raw = by_http_ordinal[rejection["http_ordinal"]]
        logical = [record for record in failed if record["label"] == label]
        require(len(logical) == 1 and logical[0]["request_id"] == rejection["request_id"], "negative logical request does not match raw response")
        matching_posts = [record for record in http if record["request_id"] == rejection["request_id"] and record["method"] == "POST" and record["route"].endswith("/v2/pipeline")]
        require(matching_posts == [raw] and raw["node_id"] == rejection["node_id"] and raw["mode"] == mode, "mixed SQL probe was retried or routed elsewhere")
        allowed_codes = {"NOT_LEADER", "COMMIT_UNKNOWN", "EXPIRED"}
        if field == "rejected_mixed_minority_read":
            allowed_codes.add("QUERY_FAILED")
        require(raw["outcome"] == "response" and raw["status"] == rejection["status"] and raw["code"] == rejection["code"] and raw["code"] in allowed_codes, "no real service-level mixed-version rejection")
        require(u64(raw["deadline_unix_ms"]) > 0 and rejection["original_server_deadline_ms"] == 2500 and rejection["response_drain_allowance_ms"] == 1500 and rejection["sql_posts"] == 1 and rejection["readiness_bypassed"] is True, "direct probe deadline/attempt contract differs")
        if field == "rejected_mixed_minority_read":
            require(raw["node_id"] != upgraded and mixed["old_minority_started_ms"] <= raw["invoked_ms"] <= raw["result_ms"] <= mixed["new_stopped_ms"], "minority strong read did not occur while both versions were live")
            restored = [record for record in requests if record["label"] == "restored_old_quorum_value"]
            require(len(restored) == 1 and restored[0]["kind"] == "read" and restored[0]["outcome"] == "success" and restored[0]["statement_sha256"] == logical[0]["statement_sha256"] and restored[0]["invoked_ms"] >= mixed["new_stopped_ms"], "the same SQL was not verified after restoring the old quorum")
            require(restored[0]["invoked_ms"] >= preparation["completed_ms"], "SQL control ran before fresh quorum recovery preparation")
        else:
            require(raw["node_id"] == upgraded and raw["invoked_ms"] >= mixed_start["new_live_ms"], "new-version probe used the old process")
    rejected_id = mixed["cancelled_request_id"]
    require(rejected_id == mixed["rejected_new_write"]["request_id"] and ("alpha", rejected_id) in cancel_ids, "uncertain mixed write lost its original identity/fence")
    legacy_cancelled(one(observed, "mixed_rejected_write_resolved")["actual_ordered_outcome"])
    old_ack = acknowledged[("alpha", mixed["old_ack_request_id"])]
    require(old_ack["label"] == "old_quorum_accepts_while_new_version_isolated", "no old-only quorum ACK witness")
    old_write = [record for record in requests if record["request_id"] == mixed["old_ack_request_id"] and record["kind"] == "write"]
    require(len(old_write) == 1 and mixed_start["new_live_ms"] <= old_write[0]["invoked_ms"] <= old_write[0]["result_ms"] <= mixed["old_minority_started_ms"], "old ACK was outside the mixed-version window")
    upgrade = one(observed, "same_directories_upgraded")
    require(local_position(upgrade["lagging_replica_caught_up"], upgraded) >= upgrade["witnessed_old_prefix"] == mixed["source_before_full_upgrade"]["applied"] > prefix, "lagging upgraded directory did not actually catch up")

    require(len(overwrites) == summary["overwrites"] == 64, "overwrite denominator differs")
    cumulative, advances = 0, 0
    start = one(observed, "bounded_history_overwrites_started")["metadata"]
    fields = {"revision": "revision", "base_revision": "baseRevision", "tail_entries": "tailEntries", "tail_bytes": "tailBytes"}
    previous = {field: u64(start[wire]) for field, wire in fields.items()}
    require(previous["revision"] == 5 and previous["tail_entries"] == previous["revision"] - previous["base_revision"] and start["cold"] is False, "upgrade did not retain the exact observed physical suffix")
    require(all(start[wire] == upgrade["alpha"][wire] for wire in fields.values()), "unexpected SQL/physical change between upgrade and overwrite accounting")
    for expected_generation, record in enumerate(overwrites, 1):
        require(record["generation"] == expected_generation, "missing/out-of-order overwrite")
        require(acknowledged[("alpha", record["request_id"])]["label"] == "overwrite_" + str(expected_generation), "overwrite missing exact ACK")
        for field, value in previous.items():
            require(u64(record["previous_" + field]) == value, "observation chain gap: " + field)
        current = {field: u64(record[field]) for field in previous}
        writes = [request for request in requests if request["request_id"] == record["request_id"] and request["kind"] == "write"]
        require(len(writes) == 1 and writes[0]["outcome"] == "success" and writes[0]["database"] == "alpha" and writes[0]["label"] == "overwrite_" + str(expected_generation), "overwrite observation has no unique successful SQL invocation")
        following = by_request_ordinal.get(writes[0]["ordinal"] + 1, {})
        require(following.get("kind") == "status" and following["database"] == "alpha" and following["label"] == "metadata" and following["outcome"] == "success" and following["invoked_ms"] >= writes[0]["result_ms"], "overwrite counters were not read immediately after the actual SQL result")
        require(following["metadata"]["cold"] is False and all(u64(following["metadata"][wire]) == current[field] for field, wire in fields.items()), "overwrite counters differ from the actual fresh metadata ledger")
        require(current["revision"] == previous["revision"] + 1, "revision gap")
        require(previous["base_revision"] <= current["base_revision"] <= current["revision"], "base regressed or exceeded head")
        require(current["tail_entries"] < 8 and current["tail_bytes"] < PROFILE["tail_bytes_trigger"], "physical tail exceeded its original trigger")
        folded = current["base_revision"] != previous["base_revision"]
        require(record["folded_transaction_bytes_excluded"] is folded, "mislabelled fold")
        if folded:
            advances += 1
            require(current["base_revision"] == current["revision"] and current["tail_entries"] == current["tail_bytes"] == 0, "fold did not retire its full tail")
            delta = 0
        else:
            delta = current["tail_bytes"] - previous["tail_bytes"]
            require(delta > 0 and current["tail_entries"] == previous["tail_entries"] + 1, "nonfolding write omitted physical bytes")
        require(u64(record["observed_new_physical_bytes"]) == delta, "physical byte estimate differs from actual tail observation")
        cumulative += delta
        require(u64(record["cumulative_observed_physical_bytes"]) == cumulative, "cumulative denominator differs")
        previous = current
    require(cumulative > PROFILE["state_bytes"] and cumulative == u64(summary["cumulative_observed_physical_bytes"]), "observed lower bound did not exceed 8MiB")
    require(advances >= 2 and advances == summary["base_advances"] and summary["fold_trigger_physical_bytes_excluded"] is True, "ongoing bounded folding was not demonstrated")
    metadata = [record["metadata"] for record in requests if record["kind"] == "status" and record["label"] == "metadata" and record["outcome"] == "success"]
    require(max(u64(value["tailEntries"]) for value in metadata) == u64(summary["maximum_tail_entries"]) < 8, "maximum observed tail entry count differs")
    require(max(u64(value["tailBytes"]) for value in metadata) == u64(summary["maximum_tail_bytes"]) < PROFILE["tail_bytes_trigger"], "maximum observed tail byte count differs")

    legacy = one(observed, "old_v2_fixture_created")
    current = one(observed, "new_archive_roundtrip_verified")
    require(legacy["archives"] and all(archive["format_version"] == 2 for archive in legacy["archives"]), "old bytes were not V2 archives")
    require(any(archive["format_version"] == 4 for archive in current["archives"]), "no real V4 object witnessed")
    require({archive["sha256"] for archive in legacy["archives"]}.issubset({archive["sha256"] for archive in current["archives"]}), "old immutable objects disappeared")
    for archive in legacy["archives"] + current["archives"]:
        require(archive["sha256"] == archive["key"].rsplit("/", 1)[1] and archive["bytes"] > 9, "archive content address differs")
    require(summary["old_archive_format"] == 2 and summary["new_archive_format"] == 4, "archive version summary differs")
    hydrated = one(observed, "old_archive_hydrated_without_metadata_rollback")["beta"]
    require(hydrated["cold"] is False and u64(hydrated["revision"]) == 2 and u64(hydrated["tailEntries"]) == 2 - u64(hydrated["baseRevision"]), "V2 archive lost its exact recovery suffix during migration")
    stopped = one(observed, "old_group_stopped")
    require(len(stopped["replicas"]) == 3 and all(value["exit"] == {"code": 0, "signal": None} for value in stopped["replicas"]), "old group did not fully stop before upgrade")
    require(stopped["all_versions_stopped_before_full_upgrade"] is True and stopped["lagging_upgraded_node_id"] == upgraded, "full upgrade discarded or concurrently reopened the mixed replica")
    killed = one(observed, "full_group_sigkill")
    require(len(killed["replicas"]) == 3 and all(value["exit"]["signal"] == "SIGKILL" for value in killed["replicas"]), "whole-group fault was not SIGKILL")
    new_files = one(observed, "new_owner_directories_recovered")["new_writer_files"]
    old_workers = {value["worker_instance"] for value in killed["prior_writer_files"]}
    require(len(new_files) >= 2 and not any(value["worker_instance"] in old_workers for value in new_files), "writer instance/path reused")
    require(all(0 <= value["main_file_bytes"] <= PROFILE["database_bytes"] for value in new_files), "SQLite file exceeded original size bound")
    require(any(value["main_file_bytes"] >= 8 * 24576 for value in new_files), "large image not physically reconstructed")
    require(new_files == summary["fresh_writer_directories"], "recovery file summary differs")
    downgrade = one(observed, "old_binary_failed_closed")
    require(len(downgrade["attempts"]) == summary["downgrade_rejected_nodes"] == 3, "missing downgrade attempt")
    require(downgrade["all_new_daemons_stopped"] is True and downgrade["no_database_reinitialization"] is True, "unsafe mixed-version downgrade")
    require({record["node_id"] for record in downgrade["local_applied_before_stop"]} == {1, 2, 3}, "downgrade did not observe every upgraded disk")
    for record in downgrade["local_applied_before_stop"]:
        require(local_position(record, record["node_id"]) >= downgrade["committed_before_stop"], "old binary was tested on a still-lagging legacy prefix")
    for attempt in downgrade["attempts"]:
        require(attempt["reason"] == "STORE_APPLICATION" and attempt["exit"]["code"] != 0 and attempt["exit"]["signal"] is None and attempt["initialize_flag_used"] is False, "incorrect downgrade failure reason")
    require(one(observed, "new_binary_reopened_without_ack_loss")["binary_and_harness_inputs_unchanged"] is True, "input changed during run")

    binaries = json.loads((directory / "binary.json").read_text())
    require(binaries["old"]["source_commit"] == "662f04133f6a869d0dae5b05467656e6deca5c12", "unpinned V2 producer")
    require(binaries["old"]["sha256"] != binaries["current"]["sha256"], "old/current binary identical")
    for entry in [binaries["old"], binaries["current"], *binaries["harness"]]:
        target = Path(entry["path"])
        require(target.stat().st_size == entry["bytes"] and sha(target) == entry["sha256"], "binary/harness identity changed: " + str(target))
    return {
        "passed": True,
        "contracts": len(NAMES),
        "acknowledged_writes": len(acks),
        "cancellation_fences": len(cancel_ids),
        "retained_request_identities": identities,
        "request_attempts": len(requests),
        "unsuccessful_attempts": failed,
        "http_attempts": len(http),
        "overwrites": len(overwrites),
        "base_advances": advances,
        "observed_physical_lower_bound_bytes": cumulative,
        "fold_trigger_bytes_excluded": True,
        "mixed_versions_rejected": True,
        "mixed_new_node_applied_before": prefix,
        "mixed_new_node_applied_after_full_upgrade": upgrade["lagging_replica_caught_up"]["status"]["applied"],
        "local_status_is_commit_confirmation": False,
        "original_results_lost": 0,
        "binary_and_harness_identities_verified": True,
        "production_source_identity_requires_build_receipt": True,
        "production_slo_passed": False,
    }


if __name__ == "__main__":
    require(len(sys.argv) == 2, "usage: check_evidence.py /absolute/completed/evidence")
    print(json.dumps(audit(Path(sys.argv[1])), indent=2))
