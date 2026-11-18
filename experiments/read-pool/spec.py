"""Frozen offered work and resource profile, independent of product outcomes."""

PROFILE = {"workers": 3, "active_per_tenant": 2, "active_per_database": 2}
SCOPES = {name: {"deployment": "1", "tenant": tenant, "database": "3101",
                 "incarnation": "1", "generation": "1"}
          for name, tenant in (("a", "7"), ("b", "8"))}
HEAD = "/scap-test/scap-object/v1/1/7/3101/head"
OTHER_HEAD = "/scap-test/scap-object/v1/1/8/3101/head"
COMMANDS = [
    {"id": "seed_a", "operation": "seed", "scope": "a", "http": 4},
    {"id": "seed_b", "operation": "seed", "scope": "b", "http": 3},
    *[{"id": name, "operation": "query", "scope": "a", "caller": "reader",
       "rows": ["1", "2"], "http": 1} for name in ("first", "second", "queued")],
    {"id": "other", "operation": "query", "scope": "b", "rows": ["1"], "http": 1},
    {"id": "write", "operation": "write", "scope": "a", "n": 2, "http": 1},
    {"id": "control", "operation": "status", "scope": "a", "http": 1},
    *[{"id": name, "operation": "query", "scope": "b", "rows": ["1"], "http": 1}
      for name in ("park_first", "park_second")],
    {"id": "warm", "operation": "query", "scope": "a", "caller": "reader", "rows": ["1", "2"], "http": 1},
    {"id": "write_again", "operation": "write", "scope": "a", "n": 3, "http": 1},
    {"id": "refresh", "operation": "query", "scope": "a", "caller": "reader", "rows": ["1", "2", "3"], "http": 1},
    {"id": "unknown", "operation": "query", "scope": "a", "caller": "reader", "error": "UNKNOWN", "http": 1},
    {"id": "query_write", "operation": "query_write", "scope": "a", "caller": "reader", "error": "ENGINE", "http": 1},
    {"id": "revoke", "operation": "revoke", "scope": "a", "http": 2},
    {"id": "denied", "operation": "query", "scope": "a", "caller": "reader", "error": "DENIED", "http": 1},
    *[{"id": "lookup_" + name, "operation": "lookup", "scope": "a", "original": name, "http": 1}
      for name in ("seed_a", "write", "write_again")],
    {"id": "final", "operation": "query", "scope": "a", "rows": ["1", "2", "3"], "http": 1},
]
