"""Frozen input denominators for the real HEAD5 segmented-index contract."""

LAST_ID = 2114
SCOPE = {"deployment": "1", "tenant": "7", "database": "991", "incarnation": "1", "generation": "1"}
PHASES = ("seed", "warm", "cold", "corrupt", "missing", "summary", "repaired")
BACKEND_VERSION = "4.51 153ab668c99731a6d29492bf6c61d0b4fa701101"
CALLS = {
    "seed": [("create", "create"), ("activate", "activate"), ("execute_first", "execute")]
            + [(f"cancel_{identity}", "cancel") for identity in range(2, LAST_ID)]
            + [("execute_last", "execute")],
    "warm": [("warm_status", "status"), ("warm_query", "query"), ("warm_first", "lookup"),
             ("warm_last", "lookup"), ("warm_cancelled", "lookup"), ("unknown", "lookup"), ("conflict", "lookup")],
    "cold": [("cold_open", "open"), ("cold_query", "query"), ("cold_first", "lookup"),
             ("cold_last", "lookup"), ("cold_cancelled", "lookup")],
    **{phase: [(phase + "_first", "lookup"), (phase + "_open", "open"),
               (phase + "_query", "query"), (phase + "_status", "status")]
       for phase in ("corrupt", "missing", "summary")},
    "repaired": [("repaired_open", "open"), ("repaired_query", "query"), ("repaired_first", "lookup"),
                 ("repaired_last", "lookup"), ("repaired_cancelled", "lookup")],
}
DEADLINES = {"client_request_ms": 40000, "seed_phase_ms": 600000, "other_phase_ms": 120000,
             "service_ready_ms": 20000, "s3_request_ms": 10000, "curl_ms": 15000,
             "ordinary_service_ms": 10000, "recovery_service_ms": 30000}
PLAN = {"schema": 1, "profile": "segmented-request-index-real-http-s3-v1", "head_format": 5,
        "immutable_format": 2, "scope": SCOPE, "owner_instance": 8871, "last_id": LAST_ID,
        "phases": list(PHASES), "calls": {phase: [list(item) for item in CALLS[phase]] for phase in PHASES},
        "deadlines": DEADLINES, "http_invocations": sum(map(len, CALLS.values())),
        "retained_entries": LAST_ID, "tracked_inputs": LAST_ID + 2, "original_sql_acks": 2,
        "cancellations": LAST_ID - 2, "backend_auth_controls": 1, "service_processes": 6,
        "original_blob_bytes": 1024, "minimum_observed_root_level": 2,
        "damage_cases": ["corrupt", "missing", "summary"],
        "aws_standard": "NOT_RUN", "production_tps": "NOT_MEASURED", "physical_gc": "DISABLED"}
