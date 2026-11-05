"""Unit regressions for the evidence auditor; no daemon, cargo, or real fault run.

The small binary encoders below construct synthetic parser fixtures only. Every
fixture lives in a temporary directory and is removed; an accepted unit fixture
is not execution evidence for any production contract.
"""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    loaded = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "path", [str(filename.parent), *sys.path]):
        spec.loader.exec_module(loaded)
    return loaded


AUDIT = module("control_evidence_audit_unit", HERE / "check_evidence.py")
BUILDER = module("control_legacy_builder_unit", HERE / "build_legacy.py")
PROBE_BUILDER = module("control_probe_builder_unit", HERE / "record_probe_build.py")
COMMIT = "f14b03d03d9216ea56b78aef9d71c5d78fd83645"
TREE = "43131a1599d2e20b4865025e2040a0796ee9cd80"
CONTRACTS = [
    "01-full-v4-control-table-and-new-bounded-faults",
    "02-real-v4-production-hot-and-cold-data",
    "03-mixed-peer-generations-fail-closed",
    "04-v4-to-v5-upgrade-cold-and-crash-recovery",
    "05-v4-binary-rejects-v5-state",
]
RESULT = b"unit-only-original-SQL-result"


def number(value, size=8):
    return value.to_bytes(size, "big")


def position(term, index):
    return number(term) + number(index)


def envelope(magic, version, payload):
    header = magic + bytes([version]) + number(len(payload)) + payload
    return header + hashlib.sha256(header).digest()


def blob(value):
    return number(len(value)) + value


def admission():
    return number(101, 16) + number(202, 16) + number(303, 16) + number(1) * 2


def state_fixture(version=5, legacy_receipts=0, control_revision=3,
                  receipt_revision=None, receipt_position=(2, 199),
                  state_position=(2, 200), receipt_present=None, result=RESULT):
    """Encode the documented v4/v5 inventory layout, without production APIs."""
    limits = (8 * 1024 * 1024, 400 * 1024, 8, 8, 4096, 128, 300 * 1024, 16384)
    header = (number(71, 16) + number(7) +
              b"".join(number(value, 4) for value in limits) +
              number(101, 16) + position(*state_position) + number(1))
    database = (number(81, 16) + number(2) + number(1) + number(4094) +
                number(1) + number(701, 16) + b"\x01" +
                number(1) + number(101, 16) + b"\x07")
    database += number(1) + bytes(56) + b"\x00"  # request epoch, retired prefix
    ticket = bytearray(144)
    ticket[88:104] = number(10, 16)
    transaction = (admission() + bytes(32) + ticket + number(1) +
                   position(1, 7) + blob(b"unit-only-physical-payload") +
                   blob(result) + bytes(32))
    database += number(1) + transaction
    database += number(1) + number(10, 16) + b"\x00" + number(0)
    database += b"\x00\x00\x00\x00" + number(0)  # lifecycle, archive, base, ACKs
    if version == 5:
        present = control_revision != 0 if receipt_present is None else receipt_present
        database += number(control_revision) + bytes([int(present)])
        if present:
            revision = control_revision if receipt_revision is None else receipt_revision
            database += number(77, 16) + admission() + bytes(32)
            database += number(revision) + position(*receipt_position) + b"\x03" + number(4094)
    old = b"".join(
        number(10000 + ordinal, 16) + admission() + bytes(64) +
        b"\x03" + number(ordinal + 2) + position(1, ordinal + 8)
        for ordinal in range(legacy_receipts)
    )
    return envelope(b"SCAPCELL", version, header + database + number(legacy_receipts) + old + b"\x00")


def discarded_result(kind=7, expected_revision=5, receipt_revision=None,
                     original_position=(2, 400), applied_position=None,
                     result_digest=None, outcome_tag=9, result_tag=None):
    archive = envelope(b"SCAPARC!", 4, b"unit-only-archive-object")
    digest = hashlib.sha256(archive).digest()
    scope = number(71, 16) + number(7) + number(81, 16) + number(2) + number(1)
    command = scope + admission() + number(expected_revision) + bytes([kind]) + number(77, 16)
    if kind == 7:
        reference = (position(2, 390) + number(1) + bytes(32) +
                     digest + number(len(archive), 4) + bytes(32))
        command += number(1) + number(701, 16) + b"\x00" + reference
    else:
        command += blob(archive)
    applied = applied_position or original_position
    revision = expected_revision + 1 if receipt_revision is None else receipt_revision
    tag = (5 if kind == 7 else 7) if result_tag is None else result_tag
    result = (position(*applied) + bytes([outcome_tag]) + number(revision) +
              position(*original_position) + bytes([tag]) +
              (digest if result_digest is None else result_digest))
    return {
        "command": envelope(b"SCAPCMD!", 4, command).hex(),
        "result": envelope(b"SCAPOUT!", 4, result).hex(),
        "term": applied[0], "index": applied[1],
        "ticket_boot": "11", "ticket_sequence": 12,
    }


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def json_lines(rows):
    return b"".join(json_bytes(row) for row in rows)


def identity(name, digest="a" * 64, size=1):
    return {"path": "/unit-only/" + name, "sha256": digest, "bytes": size}


def release_build_fixture(target, binary, prefix):
    """Synthetic Cargo observations, with exact bytes bound by the receipt."""
    command = ["cargo", "+1.90.0", "test", "--release", "--offline", "--locked",
               "--manifest-path", "/unit-only/" + target + "/Cargo.toml", "--test", target,
               "--no-run", "--message-format=json"]
    if target == "legacy":
        command.extend(["--features", "legacy-producer"])
    compiled = {**binary, "path": "/unit-only/target/release/deps/" + target}
    profile = {"opt_level": "3", "debuginfo": 0, "debug_assertions": False,
               "overflow_checks": False, "test": True}
    artifact = {
        "reason": "compiler-artifact", "package_id": "path+file:///unit-only/control-network#0.1.0",
        "target": {"name": target, "kind": ["test"], "crate_types": ["bin"]},
        "profile": profile, "executable": compiled["path"], "filenames": [compiled["path"]],
        "features": ["legacy-producer"] if target == "legacy" else [], "fresh": False,
    }
    library = identity("native/release/librocksdb.a", "9" * 64, 123)
    binding = {
        "reason": "compiler-artifact", "package_id": PROBE_BUILDER.ROCKSDB_PACKAGE,
        "target": {"name": "librocksdb_sys", "kind": ["lib"], "crate_types": ["lib"]},
        "profile": {**profile, "test": False}, "executable": None,
    }
    build_script = {
        "reason": "build-script-executed", "package_id": PROBE_BUILDER.ROCKSDB_PACKAGE,
        "linked_libs": ["static=rocksdb"], "linked_paths": ["native=/unit-only/native/release"],
        "out_dir": "/unit-only/target/release/build/librocksdb-sys/out",
    }
    files = {prefix + "-cargo.jsonl": json_lines([
        build_script, binding, artifact, {"reason": "build-finished", "success": True}]),
        prefix + "-cargo.stderr.log": b"unit-only closed build observation\n"}
    outputs = {name: identity(name, hashlib.sha256(data).hexdigest(), len(data))
               for name, data in files.items()}
    receipt = {
        "schema": 1, "complete": True, "build_profile": "release", "target": target,
        "command": command, "cargo_artifact": artifact,
        "compiled_executable": compiled, "executable": deepcopy(binary),
        "native": {"profile": "release", "profile_basis": "externally-pinned-release-library",
                   "library": library, "expected_sha256": library["sha256"],
                   "cargo_artifact": binding, "build_script": build_script, "cxxflags": "-g0"},
        "build_stdout": outputs[prefix + "-cargo.jsonl"],
        "build_stderr": outputs[prefix + "-cargo.stderr.log"], "fault_tests_executed": False,
    }
    return receipt, files


def evidence_fixture():
    """A structurally complete synthetic audit input, never a real-run result."""
    archive_digest = hashlib.sha256(
        envelope(b"SCAPARC!", 4, b"unit-only-archive-object")).hexdigest()
    binary = {
        "old": {**identity("old", "1" * 64), "source_commit": COMMIT,
                "selected_build_receipt_sha256": "1" * 64},
        "current": identity("current", "2" * 64),
        "probe": identity("probe", "3" * 64),
        "legacy_probe": identity("legacy-probe", "4" * 64),
    }
    candidate_build, candidate_files = release_build_fixture("contracts", binary["probe"], "probe")
    legacy_build, legacy_files = release_build_fixture("legacy", binary["legacy_probe"], "legacy")
    harness = ["Cargo.toml", "Cargo.lock", "src/common.rs", "src/harness.rs",
               "src/legacy_child.rs", "tests/legacy.rs"]
    source = {
        "schema": 1, "complete": True, "exit_code": 0, "synthetic_old_state": False,
        "source_commit": COMMIT, "source_tree": TREE,
        "frozen_daemon_is_separate_binary": True, "executable": binary["legacy_probe"],
        "harness_inputs": [{**identity(name), "relative_path": name} for name in harness],
        "production_inputs": [identity("source/crates/scap-cell/src/lib.rs")],
        "source_archive": identity("source.tar"),
        "command": legacy_build["command"], "probe_build": legacy_build,
        "toolchain": "cargo 1.90.0", "build_stdout": legacy_build["build_stdout"],
        "build_stderr": legacy_build["build_stderr"],
    }
    first = 3
    operations = [
        {"ordinal": ordinal, "operation_id": str(10000 + ordinal),
         "auth_epoch": ordinal + 2, "expected_revision": first + ordinal,
         "revision": first + ordinal + 1, "term": 2, "index": 100 + ordinal,
         "outcome": "ControlApplied"}
        for ordinal in range(4097)
    ]
    bounded = {
        "first_revision": first, "successful_controls": 4097, "final_revision": first + 4097,
        "last_receipt_original_index": operations[-1]["index"],
        "repeat_application_index": operations[-1]["index"] + 1,
        "exact_latest_retry": True, "retired_old_sequence": True,
        "unknown_legacy_closed": True, "retained_result_identical": True,
        "sizes": [{"completed": done, "revision": first + done, "bytes": 1500}
                  for done in [1, *range(128, 4097, 128), 4097]],
    }
    events = [
        {"event": "native_sql_seed", "observed": {"result": RESULT.hex()}},
        {"event": "more_than_4096_bounded", "observed": bounded},
    ]
    for cycle in (0, 1):
        events.append({"event": "real_cold_cycle", "observed": {
            "cycle": cycle, "archive_digest": "a" * 64, "old_prune": "ControlRetired",
            "cold_control_revision": 4200 + 4 * cycle,
            "hydrated_control_revision": 4201 + 4 * cycle,
            "original_result_identical": True, "native_sql_payload_identical": True}})
    events.extend([
        {"event": "lost_publish_interleaving", "observed": {
            "durable_publish_response_discarded": True, "no_confirmed_publication_token": True,
            "captured_command_exact": True, "original_index": 5000,
            "control_revision_before": 4210, "control_revision_after": 4211,
            "archive_digest": archive_digest,
            "interleavings": 2, "delayed_prune": "ControlRetired",
            "confirmed_stale_publication_prune": "Fenced", "physical_bytes_preserved": True}},
        {"event": "lost_hydrate_response", "observed": {
            "original_receipt_index": 5005, "exact_retry": "ControlAlreadyApplied",
            "after_interleaving": "ControlRetired"}},
    ])
    for phase in ("claimed", "activated"):
        events.append({"event": "owner_sigkill", "observed": {
            "phase": phase, "signal": 9, "old_activation": "ControlRetired",
            "refreshed_old_activation": "Fenced", "old_worker": "701", "new_worker": "702",
            "native_sql_payload_identical": True, "retained_result_identical": True}})
    events.extend([
        {"event": "learner_snapshot", "observed": {
            "node": 4, "durable_learners": [4], "direct_closed_disk_inspection": True,
            "source_snapshots": [{"node": node, "snapshot": 5999 + node} for node in (1, 2, 3)],
            "required_boundary": 5900, "installed_snapshot": 6002,
            "joined_at": 6004, "control_revision": 4220,
            "latest_receipt_revision": 4220, "latest_receipt_original_term": 2,
            "latest_receipt_original_index": 5999, "exact_latest_receipt_preserved": True,
            "receipt_postcondition_is_new_commit": False}},
        {"event": "all_voters_reopened", "observed": {
            "before_control_revision": 4220, "reopened_control_revision": 4220,
            "after_owner_recovery_control_revision": 4222,
            "latest_receipt_original_index": 5999, "retry_application_index": 6003,
            "exact_latest_receipt_preserved": True}},
    ])
    requests, http, writes = [], [], []
    kinds = ["write"] * 5 + ["mixed_read", "mixed_write", "cancel"]
    for ordinal, kind in enumerate(kinds):
        failed = kind.startswith("mixed_")
        request_id = f"{(7 if kind == 'cancel' else ordinal + 1):032x}"
        record = {
            "ordinal": ordinal, "database": "alpha", "kind": kind,
            "request_id": request_id, "request_epoch": "1",
            "invoked_ms": ordinal * 10 + 1, "result_ms": ordinal * 10 + 9,
            "outcome": "service_error" if failed else "success",
        }
        if failed:
            record["code"] = "COMMIT_UNKNOWN"
        requests.append(record)
        http.append({
            "ordinal": ordinal, "node_id": 2 if failed else 1, "method": "POST",
            "route": "/db/alpha/v2/pipeline" if kind != "cancel" else
                     f"/db/alpha/v1/requests/{request_id}/resolve",
            "request_id": request_id, "request_epoch": "1",
            "mode": "read" if kind == "mixed_read" else "write", "deadline_unix_ms": "1000",
            "invoked_ms": ordinal * 10 + 2, "result_ms": ordinal * 10 + 8,
            "outcome": "response", "status": 503 if failed else 200,
            "code": "COMMIT_UNKNOWN" if failed else None,
        })
        if kind == "write":
            writes.append({
                "database": "alpha", "request_id": request_id, "request_epoch": "1",
                "statement_sha256": hashlib.sha256(f"unit statement {ordinal}".encode()).hexdigest(),
                "result": {"columns": ["value"], "rows": [["unit"]], "rowsAffected": 1,
                           "lastInsertRowid": "1"},
            })
    mixed = {
        "event": "mixed_generations_rejected", "proxies_blocked": False,
        "old_peer_version": 3, "new_peer_version": 4, "upgraded_node": 2,
        "old_quorum_witness": {"applied": 200}, "isolated_new": {"status": {"applied": 100}},
    }
    for name, ordinal in (("read", 5), ("write", 6)):
        mixed[name] = {"posts": 1, "http_ordinal": ordinal,
                       "request_id": requests[ordinal]["request_id"], "code": "COMMIT_UNKNOWN"}
    contract_events = [
        [{"event": "rust_contracts_completed"}],
        [{"event": "real_v4_production_fixture", "producer_sha256": binary["old"]["sha256"],
          "source_commit": COMMIT, "synthetic_old_state": False, "beta": {"cold": True},
          "archives": [{"format_version": 4, "sha256": "a" * 64}]}],
        [mixed],
        [{"event": "production_cold_cycle", "cycle": cycle, "cold": {"cold": True},
          "retained_results_identical": True} for cycle in (0, 1)] +
        [{"event": "v5_recovery_preserves_originals", "original_results_verified": 6,
          "acknowledged_sql_lost": 0, "unknown_mutations_replayed": False,
          "leader_sigkill": {"signal": "SIGKILL"}, "group_sigkill": True}],
        [{"event": "old_binary_rejected_and_new_reopened", "rejections": [
            {"node_id": node, "reason": "STORE_APPLICATION", "exit": {"code": 1, "signal": None},
             "initialize_used": False, "old_compatible_configuration": True}
            for node in (1, 2, 3)]}],
    ]
    files = {
        **candidate_files, **legacy_files,
        "probe-build.json": json_bytes(candidate_build),
        "summary.json": json_bytes({
            "schema": 1, "all_contracts_passed": True, "completed": CONTRACTS,
            "processes_closed": True, "production_slo_passed": False,
            "old_state_version": 4, "new_state_version": 5,
            "old_peer_version": 3, "new_peer_version": 4,
            "acknowledged_sql_lost": 0, "unknown_mutations_replayed": False,
            "request_attempts": len(requests), "http_attempts": len(http),
            "unsuccessful_attempts": [row for row in requests if row["outcome"] != "success"],
            "original_terminal_results": 6}),
        "binary.json": json_bytes(binary),
        "legacy-source.json": json_bytes(source),
        "s3-backend.json": json_bytes({
            "version": "4.51", "commit": "153ab668c99731a6d29492bf6c61d0b4fa701101"}),
        "legacy-producer.json": json_bytes({
            "source_commit": COMMIT, "source_tree": TREE, "successful_legacy_controls": 4096,
            "initial_control_operations": 3, "auth_fences": 4093, "overflow": "Capacity",
            "synthetic_old_state": False, "retained_result": RESULT.hex()}),
        "legacy-upgrade.json": json_bytes({
            "complete": True, "legacy_controls": 4096, "new_controls_after_full_legacy_table": 3,
            "control_revision": 3, "legacy_known_retry": "AlreadyApplied",
            "unknown_legacy": "ControlRetired", "retained_result_identical": True,
            "native_sql_payload_identical": True}),
        "legacy-operations.jsonl": json_lines([
            {"ordinal": ordinal, "auth_epoch": ordinal + 2,
             "operation_id": str(10000 + ordinal), "outcome": "Administrative"}
            for ordinal in range(4093)]),
        "legacy-full-state.bin": state_fixture(4, legacy_receipts=4096, state_position=(2, 5000)),
        "legacy-upgraded-state.bin": state_fixture(5, legacy_receipts=4096,
                                                   state_position=(2, 5004), receipt_position=(2, 5004)),
        "learner-state.bin": state_fixture(
            control_revision=4220, receipt_position=(2, 5999), state_position=(2, 6002)),
        "rust-summary.json": json_bytes({
            "complete": True, "successful_new_controls": 4097, "configured_legacy_bound": 4096,
            "cold_cycles": 2, "discarded_durable_responses": 2, "owner_sigkills": 2,
            "learner_snapshot": True, "all_voters_reopened": True, "production_slo_verified": False}),
        "control-operations.jsonl": json_lines(operations),
        "rust-events.jsonl": json_lines(events),
        "lost-response-node-1.jsonl": json_lines([
            discarded_result(7, 4210, original_position=(2, 5000)),
            discarded_result(9, 4215, original_position=(2, 5005))]),
        "requests.jsonl": json_lines(requests), "http-attempts.jsonl": json_lines(http),
        "write-results.jsonl": json_lines(writes),
    }
    for name, rows in zip(CONTRACTS, contract_events):
        files[name + ".history.jsonl"] = json_lines([
            {"event": "contract_started", "name": name}, *rows,
            {"event": "contract_completed", "name": name}])
    for name in ("legacy-test.log", "legacy-upgrade-test.log", "control-test.log"):
        files[name] = b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
    return files


def close_fixture(directory, files):
    for name, data in files.items():
        (directory / name).write_bytes(data)
    manifest = {
        "schema": 1, "closed": True,
        "artifacts": [{"name": name, "bytes": len(data),
                       "sha256": hashlib.sha256(data).hexdigest()}
                      for name, data in sorted(files.items())],
    }
    (directory / "closed-manifest.json").write_bytes(json_bytes(manifest))
    return manifest


def mutate_json(files, name, change):
    record = json.loads(files[name])
    change(record)
    files[name] = json_bytes(record)


def mutate_lines(files, name, change):
    records = [json.loads(line) for line in files[name].splitlines()]
    change(records)
    files[name] = json_lines(records)


class ParserSafety(unittest.TestCase):
    def test_unsigned_fields_require_canonical_real_integers(self):
        for value in (0, "0", 1, "1", 2**64 - 1, str(2**64 - 1)):
            self.assertEqual(AUDIT.uint(value), int(value))
        for value in (True, False, None, 1.0, -1, 2**64, "", "01", "+1", " 1", "1\n", "1.0"):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                AUDIT.uint(value)
        for value in (0, "0"):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                AUDIT.uint(value, True)

    def test_envelope_rejects_changed_payload_length_magic_version_and_checksum(self):
        valid = envelope(b"SCAPCELL", 5, b"unit payload")
        self.assertEqual(AUDIT.envelope(valid, b"SCAPCELL", 5), b"unit payload")
        changed = bytearray(valid)
        changed[17] ^= 1
        for data in (bytes(changed), valid[:-1], valid + b"x",
                     envelope(b"SCAPOUT!", 5, b"unit payload"),
                     envelope(b"SCAPCELL", 4, b"unit payload")):
            with self.subTest(data=data[:17]), self.assertRaises(AssertionError):
                AUDIT.envelope(data, b"SCAPCELL", 5)

    def test_state_inventory_counts_actual_receipts_and_original_result_bytes(self):
        for version in (4, 5):
            state = AUDIT.decode_state(state_fixture(version, legacy_receipts=2), version)
            self.assertEqual(state["legacy_receipts"], 2)
            database = state["databases"][0]
            self.assertEqual(database["control_receipts"], int(version == 5))
            self.assertEqual(database["transactions"], [{
                "request_id": 10, "revision": 1,
                "result_sha256": hashlib.sha256(RESULT).hexdigest()}])
        empty = AUDIT.decode_state(state_fixture(control_revision=0), 5)
        self.assertEqual(empty["databases"][0]["control_receipts"], 0)

    def test_current_receipt_must_match_revision_presence_and_valid_original_position(self):
        invalid = [
            {"receipt_revision": 2}, {"receipt_present": False},
            {"control_revision": 0, "receipt_present": True},
            *({"receipt_position": point} for point in
              ((0, 199), (2, 0), (3, 199), (1, 200), (2, 201))),
        ]
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(AssertionError):
                AUDIT.decode_state(state_fixture(**change), 5)
        for point in ((1, 199), (2, 199), (2, 200)):
            AUDIT.decode_state(state_fixture(receipt_position=point), 5)

    def test_parser_rejects_truncated_unbounded_flags_and_unconsumed_bytes(self):
        for reader, method in (
            (AUDIT.Reader(b"\x02"), lambda value: value.flag()),
            (AUDIT.Reader(number(1_000_001)), lambda value: value.count()),
            (AUDIT.Reader(number(8 * 1024 * 1024 + 1)), lambda value: value.blob()),
            (AUDIT.Reader(b"\xff"), lambda value: value.admin()),
            (AUDIT.Reader(b"\x01"), lambda value: value.admin()),
        ):
            with self.subTest(method=method), self.assertRaises(AssertionError):
                method(reader)
        valid = state_fixture()
        for payload in (valid[17:-33], valid[17:-32] + b"\x00"):
            with self.subTest(size=len(payload)), self.assertRaises(AssertionError):
                AUDIT.decode_state(envelope(b"SCAPCELL", 5, payload), 5)

    def test_json_records_require_closure_and_unambiguous_objects(self):
        with tempfile.TemporaryDirectory(prefix="scap-control-audit-unit-") as name:
            root = Path(name)
            record = root / "events.jsonl"
            record.write_bytes(b'{"event":"one"}\n')
            self.assertEqual(AUDIT.lines(root, record.name), [{"event": "one"}])
            for raw in (b"", b'{"event":"one"}', b'{"event":"one"}\n\n',
                        b'{"event":"failed","event":"success"}\n',
                        b'{"event":"one","elapsed_ms":NaN}\n',
                        b'{"event":"one","elapsed_ms":Infinity}\n', b"[]\n", b"null\n"):
                with self.subTest(raw=raw):
                    record.write_bytes(raw)
                    with self.assertRaises((AssertionError, ValueError)):
                        AUDIT.lines(root, record.name)


class DiscardedReceiptSafety(unittest.TestCase):
    def test_publish_and_hydrate_preserve_exact_result_and_original_position(self):
        for kind in (7, 9):
            observed_kind, receipt = AUDIT.lost_result(discarded_result(kind))
            self.assertEqual(observed_kind, kind)
            self.assertEqual(receipt["revision"], 6)
            self.assertEqual(receipt["position"], {"term": 2, "index": 400})

    def test_valid_u128_boot_identity_is_not_truncated_to_a_control_sequence(self):
        row = discarded_result()
        row["ticket_boot"] = str(2**96)
        self.assertEqual(AUDIT.lost_result(row)[0], 7)

    def test_lost_ack_requires_successor_revision_and_the_same_original_position(self):
        for change in ({"receipt_revision": 5}, {"receipt_revision": 7},
                       {"applied_position": (2, 401)}, {"applied_position": (3, 400)},
                       {"outcome_tag": 10}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                AUDIT.lost_result(discarded_result(**change))

    def test_lost_ack_must_bind_the_published_or_fetched_object(self):
        for kind in (7, 9):
            for change in ({"result_digest": b"x" * 32},
                           {"result_tag": 7 if kind == 7 else 5}):
                with self.subTest(kind=kind, change=change), self.assertRaises(AssertionError):
                    AUDIT.lost_result(discarded_result(kind, **change))

    def test_position_and_ticket_observations_must_be_positive_typed_identifiers(self):
        for point in ((0, 400), (2, 0)):
            with self.subTest(point=point), self.assertRaises(AssertionError):
                AUDIT.lost_result(discarded_result(original_position=point))
        for field, value in (("term", True), ("index", True),
                             ("ticket_boot", "0"), ("ticket_sequence", 0),
                             ("ticket_boot", str(2**128)), ("ticket_sequence", str(2**64))):
            row = discarded_result(original_position=(1, 1))
            row[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                AUDIT.lost_result(row)


class ClosedManifestSafety(unittest.TestCase):
    def test_closed_inventory_binds_exact_bytes_and_rejects_extra_missing_or_changed_files(self):
        for mutation in ("extra", "missing", "changed", "failure"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                close_fixture(root, {"record.json": b"{}\n"})
                AUDIT.closed_manifest(root)
                if mutation == "extra":
                    (root / "unlisted.log").write_bytes(b"extra")
                elif mutation == "missing":
                    (root / "record.json").unlink()
                elif mutation == "changed":
                    (root / "record.json").write_bytes(b"[]\n")
                else:
                    (root / "failure.json").write_bytes(b"{}\n")
                with self.assertRaises(AssertionError):
                    AUDIT.closed_manifest(root)

    def test_manifest_types_duplicates_order_and_unsafe_names_fail_closed(self):
        mutations = [
            lambda row: row.update(schema=True),
            lambda row: row.update(closed=1),
            lambda row: row["artifacts"][0].update(bytes=True),
            lambda row: row["artifacts"][0].update(bytes=-1),
            lambda row: row["artifacts"][0].update(sha256="A" * 64),
            lambda row: row["artifacts"].append(deepcopy(row["artifacts"][0])),
            lambda row: row["artifacts"].reverse(),
            lambda row: row["artifacts"][0].update(name="../outside"),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                manifest = close_fixture(root, {"a": b"x", "b": b"y"})
                mutation(manifest)
                (root / "closed-manifest.json").write_bytes(json_bytes(manifest))
                with self.assertRaises(AssertionError):
                    AUDIT.closed_manifest(root)

    def test_duplicate_manifest_keys_and_symlinked_manifest_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "closed"
            root.mkdir()
            close_fixture(root, {"a": b"x"})
            manifest = root / "closed-manifest.json"
            original = manifest.read_bytes()
            manifest.write_bytes(original.replace(b'"closed":true', b'"closed":false,"closed":true'))
            with self.assertRaises((AssertionError, ValueError)):
                AUDIT.closed_manifest(root)
            outside = Path(name) / "external-manifest.json"
            outside.write_bytes(original)
            manifest.unlink()
            manifest.symlink_to(outside)
            with self.assertRaises(AssertionError):
                AUDIT.closed_manifest(root)

    def test_an_artifact_symlink_is_not_a_closed_private_file(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "closed"
            root.mkdir()
            close_fixture(root, {"a": b"x"})
            outside = Path(name) / "external"
            outside.write_bytes(b"x")
            (root / "a").unlink()
            (root / "a").symlink_to(outside)
            with self.assertRaises(AssertionError):
                AUDIT.closed_manifest(root)


class ReleaseProbeEvidenceSafety(unittest.TestCase):
    def inspect(self, change=None, target="contracts", accepted=False):
        binary = identity("probe", "3" * 64, 17)
        receipt, files = release_build_fixture(target, binary, "probe")
        rows = [json.loads(line) for line in files["probe-cargo.jsonl"].splitlines()]
        if change is not None:
            change(receipt, rows)
        files["probe-cargo.jsonl"] = json_lines(rows)
        receipt["build_stdout"].update(
            sha256=hashlib.sha256(files["probe-cargo.jsonl"]).hexdigest(),
            bytes=len(files["probe-cargo.jsonl"]))
        files["probe-build.json"] = json_bytes(receipt)
        with tempfile.TemporaryDirectory(prefix="scap-control-probe-audit-unit-") as name:
            root = Path(name)
            close_fixture(root, files)
            # Rehash both Cargo output and the outer manifest. Rejection must
            # come from the semantic binding, not deliberately stale hashes.
            AUDIT.closed_manifest(root)
            if accepted:
                AUDIT.probe_build(root, receipt, binary, target, "probe")
            else:
                with self.assertRaises(AssertionError):
                    AUDIT.probe_build(root, receipt, binary, target, "probe")

    def test_closed_release_builds_accept_exact_external_or_source_native_bindings(self):
        for target in ("contracts", "legacy"):
            with self.subTest(target=target, native="external"):
                self.inspect(target=target, accepted=True)

            def source_native(receipt, rows):
                native = receipt["native"]
                native.update(profile_basis="cargo-release-native-build", expected_sha256=None)
                native["build_script"]["out_dir"] = str(Path(native["library"]["path"]).parent)
                rows[0] = deepcopy(native["build_script"])

            with self.subTest(target=target, native="source"):
                self.inspect(source_native, target=target, accepted=True)

    def test_release_label_never_replaces_required_command_or_completion(self):
        changes = [
            lambda receipt, rows: receipt.update(schema=True),
            lambda receipt, rows: receipt.update(complete=1),
            lambda receipt, rows: receipt.update(fault_tests_executed=True),
            lambda receipt, rows: receipt.update(build_profile="debug"),
            lambda receipt, rows: receipt.update(target="legacy"),
            *(lambda receipt, rows, flag=flag: receipt["command"].remove(flag)
              for flag in ("--release", "--locked", "--no-run", "--message-format=json")),
            lambda receipt, rows: receipt["command"].__setitem__(
                receipt["command"].index("--test") + 1, "legacy"),
            lambda receipt, rows: rows[-1].update(success=False),
            lambda receipt, rows: rows.pop(),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.inspect(change)

    def test_actual_cargo_artifact_must_be_unique_and_equal_to_the_receipt(self):
        for change in (
            lambda receipt, rows: rows.pop(2),
            lambda receipt, rows: rows.insert(2, deepcopy(rows[2])),
            lambda receipt, rows: rows[2]["profile"].update(opt_level="0"),
            lambda receipt, rows: receipt["cargo_artifact"]["profile"].update(opt_level="0"),
            lambda receipt, rows: receipt["compiled_executable"].update(path="/unit-only/other"),
            lambda receipt, rows: receipt["executable"].update(sha256="0" * 64),
            lambda receipt, rows: receipt["compiled_executable"].update(bytes=True),
        ):
            with self.subTest(change=change):
                self.inspect(change)

    def test_consistent_debug_cargo_records_cannot_be_relabelled_release(self):
        for field, value in (("opt_level", "0"), ("debug_assertions", True), ("test", False)):
            def change(receipt, rows):
                receipt["cargo_artifact"]["profile"][field] = value
                rows[2] = deepcopy(receipt["cargo_artifact"])

            with self.subTest(field=field):
                self.inspect(change)

    def test_native_library_must_match_the_actual_static_link_and_release_binding(self):
        changes = [
            lambda native: native.update(profile="debug"),
            lambda native: native.update(expected_sha256="0" * 64),
            lambda native: native.update(profile_basis="directory-named-release"),
            lambda native: native["library"].update(path="/unit-only/other/librocksdb.a"),
            lambda native: native["build_script"].update(linked_libs=["dylib=rocksdb"]),
            lambda native: native["build_script"].update(linked_paths=["native=/unit-only/other"]),
            lambda native: native["cargo_artifact"]["profile"].update(opt_level="0"),
            lambda native: native["cargo_artifact"]["profile"].update(debug_assertions=True),
            lambda native: native["cargo_artifact"].update(package_id="unrecognized-native-binding"),
            lambda native: native.update(profile_basis="cargo-release-native-build", expected_sha256=None),
        ]
        for index, mutation in enumerate(changes):
            def change(receipt, rows):
                mutation(receipt["native"])
                rows[0] = deepcopy(receipt["native"]["build_script"])
                rows[1] = deepcopy(receipt["native"]["cargo_artifact"])

            with self.subTest(index=index):
                self.inspect(change)
        self.inspect(lambda receipt, rows: rows[0].update(out_dir="/unit-only/different-raw-record"))


class CompleteAuditSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.valid = evidence_fixture()

    def reject(self, files):
        with tempfile.TemporaryDirectory(prefix="scap-control-audit-unit-") as name:
            root = Path(name)
            close_fixture(root, files)
            # Semantic regressions must not pass merely because the manifest
            # checksum was left stale after a deliberate fixture mutation.
            AUDIT.closed_manifest(root)
            with self.assertRaises(AssertionError):
                AUDIT.check(root)

    def test_complete_structural_fixture_is_accepted_and_reported_with_exact_denominators(self):
        with tempfile.TemporaryDirectory(prefix="scap-control-audit-unit-") as name:
            root = Path(name)
            close_fixture(root, self.valid)
            self.assertEqual(AUDIT.check(root), {
                "contracts": 5, "successful_legacy_controls": 4096,
                "successful_new_controls": 4097, "actual_new_control_receipts": 1,
                "actual_retained_legacy_receipts": 4096,
                "request_attempts": 8, "unsuccessful_attempts": 2, "http_attempts": 8,
                "production_slo_passed": False})

    def test_discarded_publish_cannot_be_a_rejection_even_when_all_summary_flags_pass(self):
        files = dict(self.valid)
        rows = [json.loads(row) for row in files["lost-response-node-1.jsonl"].splitlines()]
        rows[0]["result"] = envelope(
            b"SCAPOUT!", 4, position(2, 5000) + b"\x06\x04").hex()
        files["lost-response-node-1.jsonl"] = json_lines(rows)
        self.reject(files)

    def test_resealed_discarded_receipts_cannot_change_successor_position_or_object(self):
        for kind in (7, 9):
            for change in ({"receipt_revision": 2}, {"result_digest": b"z" * 32},
                           {"applied_position": (2, 5100)}):
                with self.subTest(kind=kind, change=change):
                    files = dict(self.valid)
                    rows = [json.loads(row) for row in files["lost-response-node-1.jsonl"].splitlines()]
                    index = 0 if kind == 7 else 1
                    rows[index] = discarded_result(
                        kind, 4210 if kind == 7 else 4215,
                        original_position=(2, 5000 if kind == 7 else 5005), **change)
                    files["lost-response-node-1.jsonl"] = json_lines(rows)
                    self.reject(files)

    def test_actual_snapshot_receipts_and_retained_results_override_success_booleans(self):
        changes = [
            ("legacy-full-state.bin", state_fixture(4, legacy_receipts=4095, state_position=(2, 5000))),
            ("legacy-upgraded-state.bin", state_fixture(
                5, legacy_receipts=4096, control_revision=4,
                state_position=(2, 5004), receipt_position=(2, 5004))),
            ("learner-state.bin", state_fixture(
                control_revision=4220, receipt_position=(2, 5999),
                state_position=(2, 6002), result=b"different original result")),
            ("learner-state.bin", state_fixture(
                control_revision=4221, receipt_position=(2, 5999), state_position=(2, 6002))),
            ("learner-state.bin", state_fixture(
                control_revision=4220, receipt_position=(2, 5998), state_position=(2, 6002))),
        ]
        for filename, data in changes:
            with self.subTest(filename=filename):
                files = dict(self.valid)
                files[filename] = data
                self.reject(files)

    def test_control_counts_sequences_and_original_retry_position_are_independent_checks(self):
        changes = [
            ("control-operations.jsonl", lambda rows: rows.pop()),
            ("control-operations.jsonl", lambda rows: rows[50].update(expected_revision=999)),
            ("control-operations.jsonl", lambda rows: rows[50].update(index=rows[49]["index"])),
            ("legacy-operations.jsonl", lambda rows: rows[50].update(ordinal=49)),
            ("rust-events.jsonl", lambda rows: rows[1]["observed"].update(last_receipt_original_index=1)),
            ("rust-events.jsonl", lambda rows: rows[1]["observed"]["sizes"][-1].update(bytes=1501)),
        ]
        for filename, change in changes:
            with self.subTest(filename=filename, change=change):
                files = dict(self.valid)
                mutate_lines(files, filename, change)
                self.reject(files)

    def test_failed_and_duplicate_attempts_cannot_disappear_from_the_denominator(self):
        changes = [
            ("requests.jsonl", lambda rows: rows.pop(5)),
            ("http-attempts.jsonl", lambda rows: rows.pop(5)),
            ("requests.jsonl", lambda rows: rows[6].update(ordinal=5)),
            ("write-results.jsonl", lambda rows: rows.pop()),
            ("write-results.jsonl", lambda rows: rows.__setitem__(4, deepcopy(rows[3]))),
        ]
        for filename, change in changes:
            with self.subTest(filename=filename, change=change):
                files = dict(self.valid)
                mutate_lines(files, filename, change)
                self.reject(files)
        files = dict(self.valid)
        mutate_json(files, "summary.json", lambda row: row.update(unsuccessful_attempts=[]))
        self.reject(files)

    def test_observation_intervals_must_be_ordered_finite_and_typed(self):
        for filename in ("requests.jsonl", "http-attempts.jsonl"):
            for field, value in (("invoked_ms", -1), ("result_ms", 0),
                                 ("invoked_ms", True), ("result_ms", float("inf"))):
                with self.subTest(filename=filename, field=field, value=value):
                    files = dict(self.valid)
                    mutate_lines(files, filename, lambda rows: rows[0].update({field: value}))
                    self.reject(files)

    def test_rust_fault_completion_and_history_closure_cannot_be_inferred_from_summary(self):
        for filename, change in (
            ("rust-events.jsonl", lambda rows: rows.pop()),
            ("rust-events.jsonl", lambda rows: rows.append(deepcopy(rows[-1]))),
            (CONTRACTS[-1] + ".history.jsonl", lambda rows: rows.pop()),
            (CONTRACTS[-1] + ".history.jsonl", lambda rows: rows.append(deepcopy(rows[-1]))),
        ):
            with self.subTest(filename=filename, change=change):
                files = dict(self.valid)
                mutate_lines(files, filename, change)
                self.reject(files)
        files = dict(self.valid)
        files["control-test.log"] = b"test result: FAILED\n" + files["control-test.log"]
        self.reject(files)

    def test_wrong_source_tree_binary_or_incomplete_build_cannot_authenticate_legacy_data(self):
        for filename, change in (
            ("legacy-source.json", lambda row: row.update(source_tree="0" * 40)),
            ("legacy-source.json", lambda row: row.update(exit_code=1)),
            ("legacy-source.json", lambda row: row.update(harness_inputs=[])),
            ("legacy-source.json", lambda row: row["executable"].update(sha256="b" * 64)),
            ("binary.json", lambda row: row["old"].update(selected_build_receipt_sha256="b" * 64)),
        ):
            with self.subTest(filename=filename, change=change):
                files = dict(self.valid)
                mutate_json(files, filename, change)
                self.reject(files)

    def test_both_probe_profiles_are_checked_even_when_all_contract_flags_pass(self):
        for prefix, filename in (("probe", "probe-build.json"), ("legacy", "legacy-source.json")):
            files = dict(self.valid)
            outer = json.loads(files[filename])
            receipt = outer if prefix == "probe" else outer["probe_build"]
            receipt["cargo_artifact"]["profile"].update(opt_level="0", debug_assertions=True)
            rows = [json.loads(line) for line in files[prefix + "-cargo.jsonl"].splitlines()]
            rows[2] = deepcopy(receipt["cargo_artifact"])
            files[prefix + "-cargo.jsonl"] = json_lines(rows)
            receipt["build_stdout"].update(
                sha256=hashlib.sha256(files[prefix + "-cargo.jsonl"]).hexdigest(),
                bytes=len(files[prefix + "-cargo.jsonl"]))
            if prefix == "legacy":
                outer["build_stdout"] = receipt["build_stdout"]
            files[filename] = json_bytes(outer)
            with self.subTest(target=prefix):
                self.reject(files)


class LegacyBuildInputSafety(unittest.TestCase):
    def invoke(self, output, **options):
        arguments = ["build_legacy.py", "--repository", "/unit-only/pinned-repository",
                     "--output", str(output)]
        for key, value in options.items():
            arguments.extend(["--" + key.replace("_", "-"), str(value)])
        with mock.patch.object(sys, "argv", arguments), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return BUILDER.main()

    def test_unrecognized_source_and_nonempty_output_never_start_a_build(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with mock.patch.object(BUILDER.subprocess, "run") as run, mock.patch.object(
                    BUILDER.subprocess, "check_output") as output:
                with self.assertRaises(SystemExit):
                    self.invoke(root / "new", commit="0" * 40)
                (root / "existing").mkdir()
                sentinel = root / "existing" / "do-not-overwrite"
                sentinel.write_text("original")
                with self.assertRaisesRegex(SystemExit, "empty private"):
                    self.invoke(root / "existing")
                self.assertEqual(sentinel.read_text(), "original")
                run.assert_not_called()
                output.assert_not_called()

    def test_pinned_commit_requires_the_exact_pinned_tree_before_archiving(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
                BUILDER.subprocess, "check_output", return_value="0" * 40 + "\n"), mock.patch.object(
                BUILDER.subprocess, "run") as run:
            root = Path(name) / "new"
            with self.assertRaisesRegex(SystemExit, "pinned exact tree"):
                self.invoke(root)
            run.assert_not_called()
            self.assertFalse((root / "legacy-source.json").exists())

    def build_stub(self, root, cargo_result=0, artifacts=1, mutate=None):
        candidate = root / "candidate"
        candidate.mkdir()
        for filename in ("Cargo.toml", "Cargo.lock", "src/common.rs", "src/harness.rs",
                         "src/legacy_child.rs", "tests/legacy.rs"):
            path = candidate / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("unit-only immutable input\n")
        executable = root / "never-executed-fixture"
        executable.write_bytes(b"unit-only artifact identity")
        native_directory = root / "release-native"
        native_directory.mkdir()
        (native_directory / "librocksdb.a").write_bytes(b"unit-only static native artifact")
        release, _ = release_build_fixture("legacy", BUILDER.identity(executable), "legacy")
        release["cargo_artifact"]["executable"] = str(executable)
        release["cargo_artifact"]["filenames"] = [str(executable)]
        release["native"]["build_script"].update(
            out_dir=str(native_directory), linked_paths=["native=" + str(native_directory)])
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if command[0] == "git":
                with tarfile.open(fileobj=kwargs["stdout"], mode="w") as archive:
                    for directory in ("crates", "experiments", "experiments/sqlite-network",
                                      "experiments/sqlite-network/src"):
                        item = tarfile.TarInfo(directory)
                        item.type = tarfile.DIRTYPE
                        archive.addfile(item)
                    content = b"unit-only archived production source\n"
                    item = tarfile.TarInfo("crates/unit.rs")
                    item.size = len(content)
                    archive.addfile(item, io.BytesIO(content))
                return subprocess.CompletedProcess(command, 0)
            if mutate is not None:
                mutate(root)
            kwargs["stdout"].write(json_bytes(release["native"]["build_script"]))
            kwargs["stdout"].write(json_bytes(release["native"]["cargo_artifact"]))
            for _ in range(artifacts):
                kwargs["stdout"].write(json_bytes(release["cargo_artifact"]))
            kwargs["stdout"].write(json_bytes({"reason": "build-finished", "success": cargo_result == 0}))
            kwargs["stderr"].write(b"unit-only compiler observation\n")
            return subprocess.CompletedProcess(command, cargo_result)

        return candidate, calls, run

    def test_successful_stub_build_binds_release_records_without_executing_the_probe(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            candidate, calls, run = self.build_stub(root)
            with mock.patch.object(BUILDER, "__file__", str(candidate / "build_legacy.py")), \
                    mock.patch.object(BUILDER.subprocess, "check_output", side_effect=[TREE + "\n", "cargo 1.90.0\n"]), \
                    mock.patch.object(BUILDER.subprocess, "run", side_effect=run), \
                    mock.patch.dict(os.environ, {}, clear=True):
                self.invoke(root / "build")
            receipt = json.loads((root / "build" / "legacy-source.json").read_text())
            self.assertEqual([command[0] for command in calls], ["git", "cargo"])
            self.assertIn("--release", calls[1])
            self.assertIn("--no-run", calls[1])
            self.assertEqual(len(receipt["harness_inputs"]), 6)
            self.assertEqual(len(receipt["production_inputs"]), 1)
            self.assertEqual(receipt["probe_build"]["build_profile"], "release")
            self.assertIs(receipt["probe_build"]["fault_tests_executed"], False)
            self.assertEqual(receipt["probe_build"]["native"]["profile_basis"], "cargo-release-native-build")
            self.assertEqual(receipt["probe_build"]["build_stdout"], receipt["build_stdout"])
            self.assertEqual(receipt["executable"]["sha256"],
                             BUILDER.sha(root / "never-executed-fixture"))

    def test_external_native_requires_an_explicit_matching_release_pin_before_compilation(self):
        for mismatch in ("static", "profile", "missing_pin", "wrong_pin"):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                candidate, calls, run = self.build_stub(root)
                environment = {
                    "ROCKSDB_LIB_DIR": str(root / "release-native"), "ROCKSDB_STATIC": "1",
                    "SCAP_CONTROL_NATIVE_PROFILE": "release",
                    "SCAP_CONTROL_NATIVE_SHA256": BUILDER.sha(root / "release-native" / "librocksdb.a"),
                }
                if mismatch == "static":
                    environment["ROCKSDB_STATIC"] = "0"
                elif mismatch == "profile":
                    environment["SCAP_CONTROL_NATIVE_PROFILE"] = "debug"
                elif mismatch == "missing_pin":
                    environment.pop("SCAP_CONTROL_NATIVE_SHA256")
                else:
                    environment["SCAP_CONTROL_NATIVE_SHA256"] = "0" * 64
                with mock.patch.object(BUILDER, "__file__", str(candidate / "build_legacy.py")), \
                        mock.patch.object(BUILDER.subprocess, "check_output", return_value=TREE + "\n"), \
                        mock.patch.object(BUILDER.subprocess, "run", side_effect=run), \
                        mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaises(AssertionError):
                        self.invoke(root / "build")
                self.assertEqual([command[0] for command in calls], ["git"])
                self.assertFalse((root / "build" / "legacy-source.json").exists())

    def test_external_release_pin_is_not_inferred_from_the_directory_name(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "arbitrary-native-location"
            root.mkdir()
            library = root / "librocksdb.a"
            library.write_bytes(b"unit-only pinned static artifact")
            environment = {"ROCKSDB_LIB_DIR": str(root), "ROCKSDB_STATIC": "1",
                           "SCAP_CONTROL_NATIVE_PROFILE": "release",
                           "SCAP_CONTROL_NATIVE_SHA256": BUILDER.sha(library)}
            self.assertEqual(PROBE_BUILDER.external_native(environment), PROBE_BUILDER.identity(library))
            library.write_bytes(b"unit-only changed static artifact")
            with self.assertRaisesRegex(AssertionError, "release pin"):
                PROBE_BUILDER.external_native(environment)
            with self.assertRaisesRegex(AssertionError, "without an external"):
                PROBE_BUILDER.external_native({"SCAP_CONTROL_NATIVE_PROFILE": "release"})

    def test_coverage_environment_is_rejected_before_any_compiler_invocation(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            candidate, calls, run = self.build_stub(root)
            with mock.patch.object(BUILDER, "__file__", str(candidate / "build_legacy.py")), \
                    mock.patch.object(BUILDER.subprocess, "check_output", return_value=TREE + "\n"), \
                    mock.patch.object(BUILDER.subprocess, "run", side_effect=run), \
                    mock.patch.dict(os.environ, {"LLVM_PROFILE_FILE": "/unit-only/%m.profraw"}, clear=True):
                with self.assertRaisesRegex(SystemExit, "coverage environment"):
                    self.invoke(root / "build")
            self.assertEqual([command[0] for command in calls], ["git"])
            self.assertFalse((root / "build" / "legacy-source.json").exists())

    def test_failed_or_ambiguous_build_output_never_produces_a_source_receipt(self):
        for returncode, artifacts in ((101, 1), (0, 0), (0, 2)):
            with self.subTest(returncode=returncode, artifacts=artifacts), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                candidate, _, run = self.build_stub(root, returncode, artifacts)
                with mock.patch.object(BUILDER, "__file__", str(candidate / "build_legacy.py")), \
                        mock.patch.object(BUILDER.subprocess, "check_output", return_value=TREE + "\n"), \
                        mock.patch.object(BUILDER.subprocess, "run", side_effect=run), \
                        mock.patch.dict(os.environ, {}, clear=True):
                    with self.assertRaises(SystemExit):
                        self.invoke(root / "build")
                self.assertFalse((root / "build" / "legacy-source.json").exists())
                self.assertTrue((root / "build" / "cargo.stderr.log").read_bytes().endswith(b"\n"))

    def test_changed_harness_or_archived_source_during_build_cannot_receive_a_receipt(self):
        mutations = [
            lambda root: (root / "candidate" / "src" / "common.rs").write_text("changed"),
            lambda root: (root / "build" / "source" / "crates" / "unit.rs").write_text("changed"),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                candidate, _, run = self.build_stub(root, mutate=mutate)
                with mock.patch.object(BUILDER, "__file__", str(candidate / "build_legacy.py")), \
                        mock.patch.object(BUILDER.subprocess, "check_output", return_value=TREE + "\n"), \
                        mock.patch.object(BUILDER.subprocess, "run", side_effect=run), \
                        mock.patch.dict(os.environ, {}, clear=True):
                    with self.assertRaisesRegex(SystemExit, "inputs changed"):
                        self.invoke(root / "build")
                self.assertFalse((root / "build" / "legacy-source.json").exists())


if __name__ == "__main__":
    unittest.main()
