"""Fixed independent transactions, faults and budgets for the actual contract."""

PROFILE = {"version": 1, "max_members": 4, "max_input_bytes": 65536,
           "max_changed_pages": 2048, "max_result_bytes": 1048576}
SCOPE = {"deployment": "1", "tenant": "7", "database": "3201",
         "incarnation": "1", "generation": "1"}
HEAD = "/scap-test/scap-object/v1/1/7/3201/head"
PREFIX = "/scap-test/scap-object/v1/1/7/3201/inc/1/gen/1/storage/1/objects/"
WORKERS = {"primary": "9201", "restarted": "9202"}
PHASES = ("success", "first_failure", "middle_failure", "last_failure", "duplicate", "cancel_race", "response_loss")


def insert(number):
    return f"INSERT INTO witness VALUES({number},random()) RETURNING n,nonce"


def execute(name, identifier, sql, **extra):
    return {"id": name, "operation": "execute", "request_id": str(identifier),
            "sql": sql, "http": 1, **extra}


SEED_SQL = [
    "CREATE TABLE witness(n INTEGER PRIMARY KEY,nonce INTEGER NOT NULL)",
    "CREATE TABLE parent(n INTEGER PRIMARY KEY)",
    "CREATE TABLE child(n INTEGER PRIMARY KEY,parent INTEGER REFERENCES parent(n) DEFERRABLE INITIALLY DEFERRED)",
    insert(1),
]
GROUPS = {
    "success": [
        execute("success_a", 11, ["CREATE TABLE grouped_ddl(n INTEGER)", insert(11)]),
        execute("success_b", 12, ["INSERT INTO grouped_ddl VALUES(12)", insert(12)]),
        execute("success_c", 13, ["SELECT n FROM grouped_ddl ORDER BY n"]),
        execute("success_d", 14, [insert(14)]),
    ],
    "first_failure": [
        execute("first_failure_a", 21, ["INSERT INTO child VALUES(21,99)"], error="ENGINE"),
        execute("first_failure_b", 22, ["INSERT INTO parent VALUES(99)", insert(22)]),
        execute("first_failure_c", 23, [insert(23)]),
        execute("first_failure_d", 24, [insert(24)]),
    ],
    "middle_failure": [
        execute("middle_failure_a", 31, [insert(31)]),
        execute("middle_failure_b", 32, ["INSERT INTO child VALUES(32,199)"], error="ENGINE"),
        execute("middle_failure_c", 33, ["INSERT INTO parent VALUES(199)", insert(33)]),
        execute("middle_failure_d", 34, [insert(34)]),
    ],
    "last_failure": [
        execute("last_failure_a", 41, [insert(41)]),
        execute("last_failure_b", 42, [insert(42)]),
        execute("last_failure_c", 43, ["SELECT count(*) FROM witness"]),
        execute("last_failure_d", 44, ["INSERT INTO child VALUES(44,299)"], error="ENGINE"),
    ],
    "duplicate": [
        {"id": "duplicate_a", "operation": "duplicate", "original": "success_a", "http": 1},
        execute("duplicate_b", 52, [insert(52)]),
        execute("duplicate_c", 53, [insert(53)]),
        execute("duplicate_d", 54, [insert(54)]),
    ],
    "cancel_race": [execute("cancel_race_" + letter, 71 + offset, [insert(71 + offset)], error="CONFLICT")
                    for offset, letter in enumerate("abcd")],
    "response_loss": [execute("response_loss_" + letter, 91 + offset, [insert(91 + offset)],
                              **({"error": "UNKNOWN"} if letter == "b" else {}))
                      for offset, letter in enumerate("abcd")],
}
BASES = dict(zip(PHASES, (10, 20, 30, 40, 50, 70, 90)))
COMMANDS = [{"id": "seed", "operation": "seed", "http": 3}]
for phase in PHASES:
    COMMANDS.append(execute(phase + "_blocker", BASES[phase], [f"SELECT {BASES[phase]}"]))
    COMMANDS.extend(GROUPS[phase])
    COMMANDS.append(execute(phase + "_overflow", BASES[phase] + 9, ["SELECT 999"], error="BACKPRESSURE"))
    if phase == "cancel_race":
        COMMANDS.append({"id": "cancel_member", "operation": "cancel", "original": "cancel_race_b", "http": 1})
COMMANDS.append({"id": "resume", "operation": "resume", "worker": "restarted", "http": 3})
ORIGINALS = ["seed"] + [command["id"] for command in COMMANDS
    if command["operation"] == "execute" and command.get("error") in (None, "UNKNOWN")]
for original in ORIGINALS:
    COMMANDS.append({"id": "lookup_" + original, "operation": "lookup", "original": original,
                     "state": "committed", "worker": "restarted", "http": 1})
for letter in "abcd":
    COMMANDS.append({"id": "lookup_cancel_race_" + letter, "operation": "lookup",
        "original": "cancel_race_" + letter, "state": "cancelled" if letter == "b" else "unknown",
        "worker": "restarted", "http": 1})
FINAL_ROWS = [1, 11, 12, 14, 22, 23, 24, 31, 33, 34, 41, 42, 52, 53, 54, 91, 92, 93, 94]
COMMANDS.append({"id": "final", "operation": "query", "worker": "restarted", "http": 1})
EXPECTED_GROUP_SIZES = {"success": [4], "first_failure": [3], "middle_failure": [1, 2],
                        "last_failure": [3], "duplicate": [3], "cancel_race": [], "response_loss": [4]}
