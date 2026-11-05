"""Read-only audit of one closed, real bounded-control experiment.

This checker does not retry a failed request or start a daemon. It checks raw
sequences, all failed attempts, envelope checksums, exact on-disk receipt counts,
source/binary receipts, and completion of each independently recorded contract.
"""

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import sys

NAMES = [
    "01-full-v4-control-table-and-new-bounded-faults",
    "02-real-v4-production-hot-and-cold-data",
    "03-mixed-peer-generations-fail-closed",
    "04-v4-to-v5-upgrade-cold-and-crash-recovery",
    "05-v4-binary-rejects-v5-state",
]
KNOWN_TREES = {
    "f14b03d03d9216ea56b78aef9d71c5d78fd83645": "43131a1599d2e20b4865025e2040a0796ee9cd80",
    "99e1e31cab1fd23fa25a64211671f9ceb56d8058": "43131a1599d2e20b4865025e2040a0796ee9cd80",
    "fa34c955ab8bcb1895e1348184bd0687d07833f8": "769f3f2491a7731bc4bab86961e6a6ff79a20046",
}
SHA = re.compile(r"[0-9a-f]{64}\Z")
ROCKSDB_PACKAGE = "registry+https://github.com/rust-lang/crates.io-index#librocksdb-sys@0.17.3+10.4.2"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def uint(value, positive=False, bits=64):
    if type(value) is int:
        result = value
    else:
        require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value), "not a canonical integer")
        result = int(value)
    require(0 <= result <= 2**bits - 1 and (not positive or result > 0), f"integer outside u{bits}")
    return result


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key: " + key)
        result[key] = value
    return result


def invalid_constant(value):
    raise AssertionError("non-finite JSON number: " + value)


def decode_json(text):
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def load(directory, name):
    return decode_json((directory / name).read_text())


def lines(directory, name):
    raw = (directory / name).read_bytes()
    require(raw and raw.endswith(b"\n"), "missing closed line terminator: " + name)
    rows = raw.decode().splitlines()
    require(all(rows), "empty evidence record: " + name)
    decoded = [decode_json(line) for line in rows]
    require(all(isinstance(row, dict) for row in decoded), "JSONL record is not an object: " + name)
    return decoded


def probe_build(directory, receipt, binary, target, prefix):
    """Check actual compiler records, not a profile inferred from a file path."""
    require(type(receipt.get("schema")) is int and receipt["schema"] == 1
            and receipt.get("complete") is True and receipt.get("fault_tests_executed") is False,
            "incomplete probe build receipt")
    require(receipt["build_profile"] == "release" and receipt["target"] == target,
            "wrong probe build profile/target")
    command = receipt["command"]
    require(isinstance(command, list) and all(isinstance(value, str) for value in command)
            and all(value in command for value in ("test", "--release", "--locked", "--no-run", "--message-format=json"))
            and "--test" in command and command[command.index("--test") + 1] == target,
            "unexpected release probe command")
    for name, expected in ((prefix + "-cargo.jsonl", receipt["build_stdout"]),
                           (prefix + "-cargo.stderr.log", receipt["build_stderr"])):
        path = directory / name
        require(type(expected["bytes"]) is int and expected["bytes"] >= 0
                and path.stat().st_size == expected["bytes"] and sha(path) == expected["sha256"],
                "closed Cargo output differs from build receipt")
    records = lines(directory, prefix + "-cargo.jsonl")
    require(records[-1].get("reason") == "build-finished" and records[-1].get("success") is True,
            "Cargo build did not complete")
    artifacts = [row for row in records if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == target and row.get("executable")]
    require(len(artifacts) == 1 and artifacts[0] == receipt["cargo_artifact"],
            "probe artifact does not match its raw Cargo record")
    artifact = artifacts[0]
    profile = artifact["profile"]
    require(artifact["target"]["kind"] == ["test"] and profile["opt_level"] == "3"
            and profile["test"] is True and profile["debug_assertions"] is False,
            "probe is not an optimized release test")
    compiled, executable = receipt["compiled_executable"], receipt["executable"]
    require(compiled["path"] == artifact["executable"], "wrong compiled probe path")
    for item in (compiled, executable):
        require(type(item["bytes"]) is int and item["bytes"] > 0
                and item["bytes"] == binary["bytes"] and item["sha256"] == binary["sha256"],
                "probe build executable identity mismatch")
    native = receipt["native"]
    bindings = [row for row in records if row.get("reason") == "compiler-artifact"
                and row.get("target", {}).get("name") == "librocksdb_sys"
                and row.get("package_id") == ROCKSDB_PACKAGE]
    scripts = [row for row in records if row.get("reason") == "build-script-executed"
               and row.get("package_id") == ROCKSDB_PACKAGE]
    require(len(bindings) == len(scripts) == 1 and bindings[0] == native["cargo_artifact"]
            and scripts[0] == native["build_script"], "native input lacks its exact Cargo records")
    binding_profile = bindings[0]["profile"]
    require(native["profile"] == "release" and binding_profile["opt_level"] == "3"
            and binding_profile["test"] is False and binding_profile["debug_assertions"] is False,
            "native Rust binding is not the release profile")
    library = native["library"]
    require(type(library["bytes"]) is int and library["bytes"] > 0
            and SHA.fullmatch(library["sha256"]), "invalid native library identity")
    filename = Path(library["path"])
    require(filename.is_absolute() and filename.name == "librocksdb.a"
            and "static=rocksdb" in scripts[0]["linked_libs"]
            and "native=" + str(filename.parent) in scripts[0]["linked_paths"],
            "native library was not the linked static input")
    if native["profile_basis"] == "externally-pinned-release-library":
        require(native["expected_sha256"] == library["sha256"], "native input differs from its explicit release pin")
    else:
        require(native["profile_basis"] == "cargo-release-native-build"
                and native["expected_sha256"] is None and str(filename.parent) == scripts[0]["out_dir"],
                "source-built native profile/output binding mismatch")


def single(rows, name):
    matches = [row for row in rows if row.get("event") == name]
    require(len(matches) == 1, f"expected one {name}, got {len(matches)}")
    return matches[0]


def valid_position(position, bound=None):
    term, index = uint(position["term"], True), uint(position["index"], True)
    if bound is not None:
        upper_term, upper_index = uint(bound["term"], True), uint(bound["index"], True)
        require(term <= upper_term and index <= upper_index and (index != upper_index or term == upper_term), "receipt position is outside the durable state")
    return {"term": term, "index": index}


def envelope(data, magic, version):
    require(len(data) >= 49 and data[:8] == magic and data[8] == version, "wrong envelope identity/version")
    size = int.from_bytes(data[9:17], "big")
    require(size + 49 == len(data), "envelope size mismatch")
    require(hashlib.sha256(data[:-32]).digest() == data[-32:], "envelope checksum mismatch")
    return data[17:-32]


class Reader:
    def __init__(self, data):
        self.data, self.cursor = data, 0

    def take(self, count):
        require(type(count) is int and count >= 0 and self.cursor + count <= len(self.data), "truncated state field")
        result = self.data[self.cursor:self.cursor + count]
        self.cursor += count
        return result

    def number(self, size=8):
        return int.from_bytes(self.take(size), "big")

    def count(self, maximum=1_000_000):
        value = self.number()
        require(value <= maximum, "unbounded record count")
        return value

    def flag(self):
        value = self.number(1)
        require(value in (0, 1), "invalid presence flag")
        return value

    def blob(self):
        return self.take(self.count(8 * 1024 * 1024))

    def position(self):
        return {"term": self.number(), "index": self.number()}

    def admin(self):
        tag = self.number(1)
        sizes = {0: 0, 1: 24, 2: 0, 3: 8, 4: 8, 5: 32, 6: 32, 7: 32}
        require(tag in sizes, "unknown administrative result")
        return {"tag": tag, "data": self.take(sizes[tag])}

    def control(self):
        return {"revision": self.number(), "position": self.position(), "result": self.admin()}

    def outcome(self):
        tag = self.number(1)
        if tag in (0, 1):
            self.admin()
        elif tag in (2, 3):
            self.take(168)
        elif tag == 6:
            self.take(1)
        elif tag == 8:
            self.take(8)
        elif tag in (9, 10):
            self.control()
        else:
            require(tag in (4, 5, 7), "unknown outcome tag")
        return tag

    def finish(self):
        require(self.cursor == len(self.data), "unconsumed state bytes")


def decode_state(data, version):
    """Independent format inventory; production also decodes every snapshot.

    Count actual legacy and bounded receipts, and hash retained SQL results.
    No state or fence is manufactured or changed by this audit parser.
    """
    require(type(version) is int and version in (4, 5), "unsupported audit state version")
    reader = Reader(envelope(data, b"SCAPCELL", version))
    reader.take(24)
    limits = [reader.number(4) for _ in range(8)]
    reader.take(16)
    position = valid_position(reader.position())
    databases = []
    for _ in range(reader.count(32)):
        database_id = reader.number(16)
        reader.take(16)
        auth_epoch = reader.number()
        reader.take(24)
        reader.flag()
        reader.take(reader.count(33) * 17)
        reader.take(8 + 56)
        if reader.flag():
            reader.take(16)
        transactions = []
        for _ in range(reader.count(128)):
            reader.take(64 + 32)
            ticket = reader.take(144)
            revision = reader.number()
            reader.take(16)
            reader.blob()
            result = reader.blob()
            reader.take(32)
            transactions.append({"request_id": int.from_bytes(ticket[88:104], "big"), "revision": revision, "result_sha256": hashlib.sha256(result).hexdigest()})
        for _ in range(reader.count(128)):
            reader.take(16)
            tag = reader.number(1)
            require(tag in (0, 1), "invalid retained request tag")
            reader.take(8 if tag == 0 else 64 + 32 + 16)
        reader.flag()
        reader.flag()
        if reader.flag():
            reader.take(124)
        if reader.flag():
            reader.take(16 + 8 + 32 + 32)
            reader.blob()
        reader.take(reader.count(128) * 32)
        control_revision = None
        receipts = 0
        stored_receipt = None
        if version == 5:
            control_revision = reader.number()
            receipts = reader.flag()
            if receipts:
                reader.take(16 + 64 + 32)
                receipt = reader.control()
                valid_position(receipt["position"],position)
                stored_receipt = {"revision":receipt["revision"], "position":receipt["position"], "result_tag":receipt["result"]["tag"], "result_hex":receipt["result"]["data"].hex()}
                require(receipt["revision"] == control_revision and receipt["position"]["index"] <= position["index"], "bounded receipt not bound to current revision/position")
            require((control_revision == 0) == (receipts == 0), "missing latest bounded receipt")
        databases.append({"database_id": database_id, "auth_epoch": auth_epoch, "control_revision": control_revision, "control_receipts": receipts, "control_receipt": stored_receipt, "transactions": transactions})
    legacy = reader.count(4096)
    for _ in range(legacy):
        reader.take(16 + 64 + 32 + 32)
        reader.admin()
        reader.take(16)
    if reader.flag():
        reader.take(16)
        reader.outcome()
    reader.finish()
    return {"version": version, "bytes": len(data), "limits": limits, "position": position, "databases": databases, "legacy_receipts": legacy}


def lost_result(row):
    command = envelope(bytes.fromhex(row["command"]), b"SCAPCMD!", 4)
    require(len(command) > 145, "truncated bounded command")
    expected_revision = int.from_bytes(command[120:128], "big")
    kind = command[128]
    require(kind in (7, 9), "only Publish/Hydrate responses are discarded")
    result = Reader(envelope(bytes.fromhex(row["result"]), b"SCAPOUT!", 4))
    applied = valid_position(result.position())
    require(result.number(1) == 9, "discarded result was not ControlApplied")
    receipt = result.control()
    result.finish()
    valid_position(receipt["position"])
    observed_position=valid_position({"term":row["term"],"index":row["index"]})
    require(applied == observed_position == receipt["position"], "discarded outcome position mismatch")
    require(receipt["revision"] == expected_revision + 1, "discarded receipt changed expected sequence")
    require(receipt["result"]["tag"] == (5 if kind == 7 else 7), "discarded outcome kind mismatch")
    uint(row["ticket_boot"], True, bits=128)
    uint(row["ticket_sequence"], True)
    if kind == 7:
        source = Reader(command[145:])
        source.take(24)
        if source.flag():
            source.take(32)
        reference = source.take(124)
        source.finish()
        require(reference[56:88] == receipt["result"]["data"], "Publish result does not identify its exact reference")
    if kind == 9:
        source = Reader(command[145:])
        archive = source.blob()
        source.finish()
        require(hashlib.sha256(archive).digest() == receipt["result"]["data"], "hydrate result does not identify the fetched object")
    return kind, receipt


def closed_manifest(directory):
    require(not (directory / "failure.json").exists(), "a failed run cannot become complete")
    manifest_path = directory / "closed-manifest.json"
    require(manifest_path.is_file() and not manifest_path.is_symlink(), "manifest is not an ordinary file")
    manifest = load(directory, "closed-manifest.json")
    require(type(manifest.get("schema")) is int and manifest.get("schema") == 1 and manifest.get("closed") is True, "missing closed manifest")
    artifacts = manifest["artifacts"]
    names = [item["name"] for item in artifacts]
    require(len(names) == len(set(names)) and names == sorted(names), "duplicate or unordered artifact inventory")
    require(set(names) | {"closed-manifest.json"} == {item.name for item in directory.iterdir()}, "closed artifact inventory is incomplete")
    for item in artifacts:
        name = item["name"]
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) and name != "closed-manifest.json", "unsafe artifact path")
        filename = directory / name
        require(filename.is_file() and not filename.is_symlink(), "artifact is not an ordinary file")
        require(filename.stat().st_size == uint(item["bytes"]) and sha(filename) == item["sha256"], "artifact bytes changed: " + name)


def check(directory):
    directory = Path(directory)
    closed_manifest(directory)
    summary, binary, source = load(directory, "summary.json"), load(directory, "binary.json"), load(directory, "legacy-source.json")
    require(type(summary.get("schema")) is int and summary["schema"] == 1, "wrong summary schema")
    require(summary.get("all_contracts_passed") is True and summary["completed"] == NAMES, "missing required contracts")
    require(summary.get("processes_closed") is True and summary.get("production_slo_passed") is False, "scope/closure claim changed")
    require(summary["old_state_version"] == 4 and summary["new_state_version"] == 5 and summary["old_peer_version"] == 3 and summary["new_peer_version"] == 4, "wrong format generations")
    require(summary.get("acknowledged_sql_lost") == 0 and summary.get("unknown_mutations_replayed") is False, "SQL correctness claim failed")
    for key in ("old", "current", "probe", "legacy_probe"):
        require(SHA.fullmatch(binary[key]["sha256"]) and uint(binary[key]["bytes"], True), "invalid binary receipt")
    require(binary["old"]["source_commit"] in KNOWN_TREES, "unrecognized old source")
    require(binary["old"]["sha256"] == binary["old"]["selected_build_receipt_sha256"] != binary["current"]["sha256"], "old/current binary identity mismatch")
    require(source.get("complete") is True and source.get("exit_code") == 0 and source.get("synthetic_old_state") is False, "old probe build incomplete")
    require(source["source_commit"] in KNOWN_TREES and source["source_tree"] == KNOWN_TREES[source["source_commit"]], "old probe source/tree mismatch")
    require(source["executable"]["sha256"] == binary["legacy_probe"]["sha256"] and source["executable"]["bytes"] == binary["legacy_probe"]["bytes"], "probe was not the source-bound executable")
    require(source.get("frozen_daemon_is_separate_binary") is True, "old probe conflated with frozen daemon")
    require(source["harness_inputs"] and source["production_inputs"], "missing legacy compile inputs")
    require("--locked" in source["command"] and "--offline" in source["command"] and "legacy-producer" in source["command"], "unexpected legacy build command")
    require(source["build_stdout"]["bytes"] > 0 and source["build_stderr"]["bytes"] >= 0, "legacy build output missing")
    candidate_build = load(directory, "probe-build.json")
    probe_build(directory, candidate_build, binary["probe"], "contracts", "probe")
    probe_build(directory, source["probe_build"], binary["legacy_probe"], "legacy", "legacy")
    require(source["command"] == source["probe_build"]["command"]
            and source["build_stdout"] == source["probe_build"]["build_stdout"]
            and source["build_stderr"] == source["probe_build"]["build_stderr"],
            "legacy source receipt disagrees with its actual build")
    s3 = load(directory, "s3-backend.json")
    require(s3["version"] == "4.51" and s3["commit"] == "153ab668c99731a6d29492bf6c61d0b4fa701101", "fake or unpinned archive backend")

    histories = []
    for name in NAMES:
        rows = lines(directory, name + ".history.jsonl")
        require(rows[0].get("event") == "contract_started" and rows[0]["name"] == name, "contract did not start")
        require(rows[-1].get("event") == "contract_completed" and rows[-1]["name"] == name, "contract did not close")
        require(sum(row.get("event") == "contract_completed" for row in rows) == 1, "duplicate completion")
        histories.extend(rows)
    for name in ("legacy-test.log", "legacy-upgrade-test.log", "control-test.log"):
        output = (directory / name).read_text()
        require(output.strip().splitlines()[-1].startswith("test result: ok. 1 passed; 0 failed") and "test result: FAILED" not in output, "Rust test did not finish: " + name)

    legacy, upgraded = load(directory, "legacy-producer.json"), load(directory, "legacy-upgrade.json")
    require(legacy["source_commit"] == source["source_commit"] and legacy["source_tree"] == source["source_tree"], "old fixture producer source mismatch")
    require(legacy["successful_legacy_controls"] == 4096 and legacy["initial_control_operations"] == 3 and legacy["auth_fences"] == 4093 and legacy["overflow"] == "Capacity" and legacy["synthetic_old_state"] is False, "old capacity fixture incomplete")
    old_ops = lines(directory, "legacy-operations.jsonl")
    require(len(old_ops) == 4093, "old controls missing")
    for index, row in enumerate(old_ops):
        require(uint(row["ordinal"]) == index and uint(row["auth_epoch"]) == index + 2 and row["operation_id"] == str(10000 + index) and row["outcome"] == "Administrative", "old control trace mismatch")
    require(upgraded.get("complete") is True and upgraded["legacy_controls"] == 4096 and upgraded["new_controls_after_full_legacy_table"] == 3 and upgraded["control_revision"] == 3, "full legacy table blocked new control")
    require(upgraded["legacy_known_retry"] == "AlreadyApplied" and upgraded["unknown_legacy"] == "ControlRetired", "legacy receipt namespace not closed")
    require(upgraded["retained_result_identical"] is True and upgraded["native_sql_payload_identical"] is True, "legacy upgrade lost original SQL")
    old_state = decode_state((directory / "legacy-full-state.bin").read_bytes(), 4)
    new_state = decode_state((directory / "legacy-upgraded-state.bin").read_bytes(), 5)
    require(old_state["legacy_receipts"] == new_state["legacy_receipts"] == 4096, "actual legacy receipt count changed")
    require(old_state["limits"][4] == new_state["limits"][4] == 4096, "legacy cap was raised")
    require(len(old_state["databases"]) == len(new_state["databases"]) == 1, "wrong full-table fixture scope")
    require(new_state["databases"][0]["control_receipts"] == 1 and new_state["databases"][0]["control_revision"] == 3, "not one actual bounded receipt after upgrade")
    expected_legacy_result = hashlib.sha256(bytes.fromhex(legacy["retained_result"])).hexdigest()
    for state in (old_state, new_state):
        require(state["databases"][0]["transactions"] == [{"request_id": 10, "revision": 1, "result_sha256": expected_legacy_result}], "actual old retained result changed")

    rust = load(directory, "rust-summary.json")
    require(rust.get("complete") is True and rust["successful_new_controls"] == 4097 and rust["configured_legacy_bound"] == 4096, "new control stress incomplete")
    require(rust["cold_cycles"] == 2 and rust["discarded_durable_responses"] == 2 and rust["owner_sigkills"] == 2 and rust["learner_snapshot"] is True and rust["all_voters_reopened"] is True and rust["production_slo_verified"] is False, "Rust fault summary incomplete")
    operations = lines(directory, "control-operations.jsonl")
    require(len(operations) == 4097, "not more than 4096 actual successes")
    events = lines(directory, "rust-events.jsonl")
    expected_events = Counter({"native_sql_seed": 1, "more_than_4096_bounded": 1, "real_cold_cycle": 2, "lost_publish_interleaving": 1, "lost_hydrate_response": 1, "owner_sigkill": 2, "learner_snapshot": 1, "all_voters_reopened": 1})
    require(Counter(row["event"] for row in events) == expected_events, "missing/duplicate Rust fault contract")
    seed = single(events, "native_sql_seed")["observed"]
    bounded = single(events, "more_than_4096_bounded")["observed"]
    first = uint(bounded["first_revision"], True)
    prior_index = 0
    for ordinal, row in enumerate(operations):
        require(uint(row["ordinal"]) == ordinal and row["operation_id"] == str(10000 + ordinal) and uint(row["auth_epoch"]) == ordinal + 2, "duplicate or missing new control")
        require(row["expected_revision"] == first + ordinal and row["revision"] == first + ordinal + 1, "new control sequence has a gap/rebase")
        require(row["outcome"] == "ControlApplied" and uint(row["index"], True) > prior_index and uint(row["term"], True), "not a distinct durable ordered success")
        prior_index = row["index"]
    require(bounded["successful_controls"] == 4097 and bounded["final_revision"] == first + 4097, "stress summary disagrees")
    require(bounded["last_receipt_original_index"] == prior_index < bounded["repeat_application_index"], "latest retry did not preserve original position")
    for flag in ("exact_latest_retry", "retired_old_sequence", "unknown_legacy_closed", "retained_result_identical"):
        require(bounded[flag] is True, "control replay invariant failed")
    sizes = bounded["sizes"]
    require(sizes[0]["completed"] == 1 and sizes[-1]["completed"] == 4097 and len(sizes) >= 33, "missing bounded-size observations")
    require(len({row["bytes"] for row in sizes}) == 1 and 0 < sizes[0]["bytes"] < 100_000, "encoded state grew with controls")
    for row in sizes:
        require(row["revision"] == first + row["completed"], "size observation not bound to sequence")
    cycles = [row["observed"] for row in events if row["event"] == "real_cold_cycle"]
    require([row["cycle"] for row in cycles] == [0, 1], "cold cycles missing")
    for row in cycles:
        require(SHA.fullmatch(row["archive_digest"]) and row["old_prune"] == "ControlRetired" and row["hydrated_control_revision"] == row["cold_control_revision"] + 1, "delayed prune was not fenced after hydration")
        require(row["original_result_identical"] is True and row["native_sql_payload_identical"] is True, "cold recovery lost data")
    publish = single(events, "lost_publish_interleaving")["observed"]
    require(publish["durable_publish_response_discarded"] is True and publish["no_confirmed_publication_token"] is True and publish["interleavings"] == 2 and publish["delayed_prune"] == "ControlRetired" and publish["confirmed_stale_publication_prune"] == "Fenced" and publish["physical_bytes_preserved"] is True, "lost Publish permitted stale pruning")
    lost = []
    for filename in sorted(directory.glob("lost-response-node-*.jsonl")):
        lost.extend(lines(directory, filename.name))
    require(len(lost) == 2, "discarded result evidence missing")
    discarded = [lost_result(row) for row in lost]
    require(sorted(kind for kind, _ in discarded) == [7, 9], "wrong discarded control commands")
    published_receipt = next(receipt for kind, receipt in discarded if kind == 7)
    require(publish["captured_command_exact"] is True and publish["original_index"] == published_receipt["position"]["index"] and publish["control_revision_before"] + 1 == publish["control_revision_after"] == published_receipt["revision"] and publish["archive_digest"] == published_receipt["result"]["data"].hex(), "lost Publish did not apply its exact intended command")
    hydrate = single(events, "lost_hydrate_response")["observed"]
    receipt = next(receipt for kind, receipt in discarded if kind == 9)
    require(hydrate["original_receipt_index"] == receipt["position"]["index"] and hydrate["exact_retry"] == "ControlAlreadyApplied" and hydrate["after_interleaving"] == "ControlRetired", "lost Hydrate receipt not preserved")
    crashes = [row["observed"] for row in events if row["event"] == "owner_sigkill"]
    require({row["phase"] for row in crashes} == {"claimed", "activated"}, "missing claim/activation crash boundary")
    for row in crashes:
        require(row["signal"] == 9 and row["old_activation"] == "ControlRetired" and row["refreshed_old_activation"] == "Fenced" and row["old_worker"] != row["new_worker"], "old owner not fenced")
        require(row["native_sql_payload_identical"] is True and row["retained_result_identical"] is True, "crash recovery lost SQL")
    learner = single(events, "learner_snapshot")["observed"]
    require(learner["node"] == 4 and learner["durable_learners"] == [4] and learner["direct_closed_disk_inspection"] is True, "learner not inspected on real durable disk")
    require(len(learner["source_snapshots"]) == 3 and all(row["snapshot"] >= learner["required_boundary"] for row in learner["source_snapshots"]), "a source retained a pre-boundary snapshot")
    require(learner["installed_snapshot"] >= min(row["snapshot"] for row in learner["source_snapshots"]) and learner["joined_at"] > learner["required_boundary"], "learner did not install required snapshot")
    installed = decode_state((directory / "learner-state.bin").read_bytes(), 5)
    require(installed["legacy_receipts"] == 0 and len(installed["databases"]) == 1 and installed["databases"][0]["control_receipts"] == 1, "new controls retained more than one actual receipt")
    require(installed["databases"][0]["control_revision"] == learner["control_revision"] and installed["position"]["index"] == learner["installed_snapshot"], "snapshot revision/position mismatch")
    preserved = installed["databases"][0]["control_receipt"]
    require(learner["exact_latest_receipt_preserved"] is True and learner["receipt_postcondition_is_new_commit"] is False, "snapshot receipt audit misclassified or absent")
    require(preserved["revision"] == learner["latest_receipt_revision"] == learner["control_revision"] and preserved["position"] == {"term":learner["latest_receipt_original_term"], "index":learner["latest_receipt_original_index"]}, "actual snapshot lost the exact original control receipt")
    seed_digest = hashlib.sha256(bytes.fromhex(seed["result"])).hexdigest()
    require(installed["databases"][0]["transactions"] == [{"request_id": 10, "revision": 1, "result_sha256": seed_digest}], "learner snapshot lost original retained result")
    reopened = single(events, "all_voters_reopened")["observed"]
    require(reopened["before_control_revision"] == reopened["reopened_control_revision"] == learner["control_revision"] and reopened["after_owner_recovery_control_revision"] == learner["control_revision"] + 2, "restart rebased/lost the sequence")

    require(reopened["exact_latest_receipt_preserved"] is True and reopened["latest_receipt_original_index"] == learner["latest_receipt_original_index"] < reopened["retry_application_index"], "reopened quorum did not preserve the exact original control receipt")
    requests, http = lines(directory, "requests.jsonl"), lines(directory, "http-attempts.jsonl")
    for rows in (requests, http):
        require([uint(row["ordinal"]) for row in rows] == list(range(len(rows))), "attempt denominator has gaps")
        for row in rows:
            require(type(row["invoked_ms"]) in (int, float) and type(row["result_ms"]) in (int, float) and math.isfinite(row["invoked_ms"]) and math.isfinite(row["result_ms"]) and 0 <= row["invoked_ms"] <= row["result_ms"], "invalid observation interval")
    failures = [row for row in requests if row["outcome"] != "success"]
    require(summary["request_attempts"] == len(requests) and summary["http_attempts"] == len(http) and summary["unsuccessful_attempts"] == failures, "failure denominator changed")
    writes = lines(directory, "write-results.jsonl")
    write_calls = [row for row in requests if row["kind"] == "write"]
    require(len(writes) >= 5 and len(writes) == len(write_calls), "successful SQL/result denominator changed")
    write_keys = [(row["database"], row["request_id"]) for row in writes]
    require(len(set(write_keys)) == len(write_keys) and set(write_keys) == {(row["database"], row["request_id"]) for row in write_calls}, "missing/duplicate original SQL result")
    require(all(row["outcome"] == "success" for row in write_calls), "uncertain SQL mutation retried")
    for row in writes:
        require(row["database"] in ("alpha", "beta") and re.fullmatch(r"[0-9a-f]{32}", row["request_id"]) and uint(row["request_epoch"]) == 1 and SHA.fullmatch(row["statement_sha256"]), "invalid original write identity")
    cancelled = [row for row in requests if row["kind"] == "cancel" and row["outcome"] == "success"]
    require(summary["original_terminal_results"] == len(writes) + len(cancelled), "retained terminal denominator changed")
    old_producer = single(histories, "real_v4_production_fixture")
    require(old_producer["producer_sha256"] == binary["old"]["sha256"] and old_producer["source_commit"] == binary["old"]["source_commit"] and old_producer["synthetic_old_state"] is False and old_producer["beta"]["cold"] is True, "old production fixture provenance mismatch")
    require(old_producer["archives"] and all(row["format_version"] == 4 and SHA.fullmatch(row["sha256"]) for row in old_producer["archives"]), "old production archive missing")
    recovery = single(histories, "v5_recovery_preserves_originals")
    require(recovery["original_results_verified"] == summary["original_terminal_results"] and recovery["acknowledged_sql_lost"] == 0 and recovery["unknown_mutations_replayed"] is False and recovery["leader_sigkill"]["signal"] == "SIGKILL" and recovery["group_sigkill"] is True, "production crash/SQL verification incomplete")
    mixed = single(histories, "mixed_generations_rejected")
    require(mixed["proxies_blocked"] is False and mixed["old_peer_version"] == 3 and mixed["new_peer_version"] == 4, "mixed protocol proof used a network partition")
    require(mixed["old_quorum_witness"]["applied"] > mixed["isolated_new"]["status"]["applied"], "new peer applied old quorum progress")
    for field in ("read", "write"):
        row = mixed[field]
        attempt = http[row["http_ordinal"]]
        require(row["posts"] == 1 and attempt["request_id"] == row["request_id"] and attempt["node_id"] == mixed["upgraded_node"] and attempt["code"] == row["code"], "mixed peer rejection is not its actual attempt")
        require(row["code"] in ("NOT_LEADER", "COMMIT_UNKNOWN", "EXPIRED"), "mixed request unexpectedly accepted")
    production_cycles = [row for row in histories if row.get("event") == "production_cold_cycle"]
    require([row["cycle"] for row in production_cycles] == [0, 1] and all(row["cold"]["cold"] is True and row["retained_results_identical"] is True for row in production_cycles), "production cold cycles incomplete")
    downgrade = single(histories, "old_binary_rejected_and_new_reopened")
    require(len(downgrade["rejections"]) == 3 and {row["node_id"] for row in downgrade["rejections"]} == {1, 2, 3}, "not all old daemons rejected")
    for row in downgrade["rejections"]:
        require(row["reason"] == "STORE_APPLICATION" and row["exit"]["code"] not in (None, 0) and row["exit"]["signal"] is None and row["initialize_used"] is False and row["old_compatible_configuration"] is True, "downgrade failed for an unrelated reason")
    return {"contracts": len(NAMES), "successful_legacy_controls": 4096, "successful_new_controls": len(operations), "actual_new_control_receipts": installed["databases"][0]["control_receipts"], "actual_retained_legacy_receipts": new_state["legacy_receipts"], "request_attempts": len(requests), "unsuccessful_attempts": len(failures), "http_attempts": len(http), "production_slo_passed": False}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_evidence.py CLOSED_EVIDENCE_DIRECTORY")
    print(json.dumps(check(Path(sys.argv[1])), sort_keys=True))
