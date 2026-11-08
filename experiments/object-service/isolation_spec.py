"""Frozen workload and deadline denominators; contains no controller logic."""

PHASES = ("seed", "keep_b_hot", "cold_a", "during_cold", "after_release")
BACKEND_VERSION = "4.51 153ab668c99731a6d29492bf6c61d0b4fa701101"
SCOPES = {name: {"deployment": "1", "tenant": "7", "database": database,
                 "incarnation": "1", "generation": "1"}
          for name, database in (("a", "101"), ("b", "202"), ("c", "303"))}
ADMISSION = {"active_database_actors": 2, "active_database_actors_per_tenant": 2,
             "actor_idle_timeout_ms": 3000, "control_workers": 1, "queued_total": 16,
             "queued_per_tenant": 12, "queued_per_database": 8, "reserved_controls": 2,
             "data_intake": 4, "control_intake": 2, "recovery_intake": 2,
             "max_body_bytes": 2097152, "timeout_ms": 5000, "recovery_timeout_ms": 20000}
CACHE = {"pages_per_actor": 65536, "parallel_recoveries": 1}
DEADLINES = {"client_request_ms": 25000, "client_phase_ms": 40000,
             "gate_arrival_ms": 5000, "gate_hold_ms": 12000,
             "hot_probe_ms": 4000, "s3_request_ms": 15000,
             "keep_b_period_ms": 750, "service_ready_ms": 20000}
CALLS = {
    "seed": [(name + "_" + operation, name, operation)
             for name in ("a", "b") for operation in ("create", "activate", "execute")],
    "keep_b_hot": [("b_keep_" + str(index), "b", "query") for index in range(6)],
    "cold_a": [("a_cold_open", "a", "open")],
    "during_cold": [("b_while_a_blocked", "b", "query"), ("c_at_capacity", "c", "query"),
                    ("a_control_while_blocked", "a", "status"), ("b_after_backpressure", "b", "query")],
    "after_release": [("a_resident_query", "a", "query"), ("b_still_resident", "b", "query"),
                      ("a_original_lookup", "a", "lookup"), ("b_original_lookup", "b", "lookup")],
}
PLAN = {"schema": 1, "profile": "bounded-actor-real-http-s3-v1", "phases": list(PHASES),
        "scopes": SCOPES, "admission": ADMISSION, "cache": CACHE, "deadlines": DEADLINES,
        "owner_instance": 5001, "blob_bytes": {"a": 393216, "b": 32768},
        "calls": {phase: [list(call) for call in CALLS[phase]] for phase in PHASES},
        "http_invocations": 21, "http_successes": 20, "backpressure_responses": 1,
        "unique_sql_inputs": 2, "original_commit_responses": 2, "original_result_lookups": 2,
        "successful_queries": 10, "gate": "first chunk of A's original committed page tree",
        "auth_control_requests": 1, "aws_standard": "NOT_RUN", "production_tps": "NOT_MEASURED"}
