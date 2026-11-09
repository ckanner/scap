"""Finite offered metadata inputs; no product or independent-oracle logic."""

WORKERS = {"S": "8101", "M": "8202"}
NAMES = ("success", "get_unknown", "put_unknown", "stale_412", "permission", "known_quarantine")
SCOPES = {name: {"deployment": "1", "tenant": "7", "database": str(2101 + index),
                 "incarnation": "1", "generation": "1"} for index, name in enumerate(NAMES)}
PRINCIPALS = {"writer": "11", "manager": "12", "reader": "13"}
BASE_POLICY = [
    {"principal": "11", "read": True, "write": True, "admin": False},
    {"principal": "12", "read": True, "write": False, "admin": True},
    {"principal": "13", "read": True, "write": False, "admin": False},
]
NEXT_POLICY = [{**row, "write": True} if row["principal"] == "13" else dict(row) for row in BASE_POLICY]
SEED_SQL = ("CREATE TABLE witness(n INTEGER PRIMARY KEY)",
            "INSERT INTO witness(n) VALUES(1) RETURNING n")
DEADLINES = {"ordinary_ms": 15000, "recovery_ms": 30000, "s3_ms": 10000,
             "client_ms": 20000, "owner_ms": 35000, "ready_seconds": 20,
             "child_seconds": 40, "gate_seconds": 10, "curl_seconds": 8,
             "actor_idle_ms": 5000}
LIMITS = {"proxy_body_bytes": 4 * 1024 * 1024, "http_request_bytes": 65536,
          "node_line_bytes": 1024 * 1024}
COMMANDS = {}


def command(identifier, worker, scope, operation, *, caller="manager", http_status=200, **fields):
    assert identifier not in COMMANDS
    COMMANDS[identifier] = {"id": identifier, "worker": worker, "scope": scope,
                            "operation": operation, "caller": caller, "http_status": http_status, **fields}


for index, name in enumerate(NAMES):
    nonce = 10000 + index * 10
    command(f"s_{name}_create", "S", name, "create", caller="writer", nonce=str(nonce))
    command(f"s_{name}_activate", "S", name, "activate", caller="writer",
            revision="1", nonce=str(nonce + 1), expected_worker=WORKERS["S"])
    command(f"s_{name}_execute", "S", name, "execute", caller="writer")
    command(f"s_{name}_policy", "S", name, "policy", caller="writer",
            revision="3", nonce=str(nonce + 2), permissions=BASE_POLICY)

command("m_success_status_before", "M", "success", "status")
command("m_success_takeover", "M", "success", "takeover", revision="4", nonce="20001", expected_worker=WORKERS["M"])
command("m_success_policy", "M", "success", "policy", revision="5", nonce="20002", permissions=NEXT_POLICY)
command("m_success_status_after", "M", "success", "status")
command("m_get_unknown_takeover", "M", "get_unknown", "takeover", http_status=503,
        revision="4", nonce="21001", expected_worker=WORKERS["M"])
command("o_get_unknown_status", "S", "get_unknown", "status")
command("m_put_unknown_policy", "M", "put_unknown", "policy", http_status=503,
        revision="4", nonce="22001", permissions=NEXT_POLICY)
command("o_put_unknown_status", "S", "put_unknown", "status")
command("m_stale_takeover", "M", "stale_412", "takeover", http_status=409,
        revision="4", nonce="23001", expected_worker=WORKERS["M"])
command("o_stale_policy", "S", "stale_412", "policy", revision="4", nonce="23002", permissions=NEXT_POLICY)
command("m_permission_takeover", "M", "permission", "takeover", caller="reader", http_status=403,
        revision="4", nonce="24001", expected_worker=WORKERS["M"])
command("m_permission_policy", "M", "permission", "policy", caller="reader", http_status=403,
        revision="4", nonce="24002", permissions=NEXT_POLICY)
command("o_permission_status", "S", "permission", "status")
command("m_quarantine_bad_status", "M", "known_quarantine", "status", http_status=409)
command("m_quarantine_repaired_status", "M", "known_quarantine", "status")
command("m_quarantine_takeover", "M", "known_quarantine", "takeover", http_status=409,
        revision="4", nonce="25001", expected_worker=WORKERS["M"])
command("m_quarantine_policy", "M", "known_quarantine", "policy", http_status=409,
        revision="4", nonce="25002", permissions=NEXT_POLICY)

FAILURES = {"m_get_unknown_takeover": "UNKNOWN", "m_put_unknown_policy": "UNKNOWN",
            "m_stale_takeover": "CONFLICT", "m_permission_takeover": "DENIED",
            "m_permission_policy": "DENIED", "m_quarantine_bad_status": "CORRUPT",
            "m_quarantine_takeover": "CORRUPT", "m_quarantine_policy": "CORRUPT"}
MAINTENANCE = [
    {"id": "f_quarantine_get", "method": "GET", "scope": "known_quarantine"},
    {"id": "f_quarantine_corrupt", "method": "PUT", "scope": "known_quarantine"},
    {"id": "f_quarantine_restore", "method": "PUT", "scope": "known_quarantine"},
]

PLAN = {"schema": 1, "profile": "metadata-head-only-real-transport-v1", "workers": WORKERS,
        "scopes": SCOPES, "seed_scopes": list(NAMES), "principals": PRINCIPALS,
        "base_policy": BASE_POLICY, "next_policy": NEXT_POLICY, "seed_sql": list(SEED_SQL),
        "seed_nonce_base": 10000, "deadlines": DEADLINES, "commands": list(COMMANDS.values()),
        "maintenance": MAINTENANCE, "limits": LIMITS,
        "expected": {"M_http": 13, "S_http": 28, "total_http": 41,
                     "M_head_get": 13, "M_head_put": 4, "F_s3": 3, "seed_ack": 6},
        "claims": {"aws_standard": "NOT_RUN", "production_slo": "NOT_RUN",
                   "native_payload_health_of_M": "NOT_PROVED", "internal_dispatch_times": "NOT_OBSERVED"}}


def head_path(name):
    return "/scap-test/scap-object/v1/1/7/" + SCOPES[name]["database"] + "/head"
