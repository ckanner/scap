"""Bind a release probe to actual Cargo output and its static RocksDB input.

This records a build, not a fault-test verdict. An external native library needs
an explicitly selected release-profile SHA; a directory name is not evidence of
its profile. CI can instead build the pinned native source through Cargo.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

ROCKSDB_PACKAGE = "registry+https://github.com/rust-lang/crates.io-index#librocksdb-sys@0.17.3+10.4.2"
SHA = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def identity(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def one(records, predicate, label):
    found = [record for record in records if predicate(record)]
    require(len(found) == 1, "expected one exact " + label)
    return found[0]


def release_profile(artifact, test):
    profile = artifact["profile"]
    require(profile["opt_level"] == "3" and profile["debug_assertions"] is False
            and profile["test"] is test, "probe/native Rust binding is not the release profile")


def external_native(environment):
    """Check a selected prebuilt input before compilation and again at receipt time."""
    directory = environment.get("ROCKSDB_LIB_DIR")
    if not directory:
        require(not environment.get("SCAP_CONTROL_NATIVE_SHA256")
                and not environment.get("SCAP_CONTROL_NATIVE_PROFILE"),
                "native pin supplied without an external native input")
        return None
    require(environment.get("ROCKSDB_STATIC") == "1", "external RocksDB must be static")
    require(environment.get("SCAP_CONTROL_NATIVE_PROFILE") == "release",
            "external RocksDB needs an explicit release-profile selection")
    expected = environment.get("SCAP_CONTROL_NATIVE_SHA256", "")
    require(SHA.fullmatch(expected), "external RocksDB needs its pinned release SHA256")
    library = identity(Path(directory) / "librocksdb.a")
    require(library["sha256"] == expected, "external native library does not match its release pin")
    return library


def record(stdout, stderr, executable, target, command, environment=None, native_before=None):
    environment = os.environ if environment is None else environment
    require(target in ("contracts", "legacy"), "unexpected control probe target")
    require(all(value in command for value in ("test", "--release", "--locked", "--no-run", "--message-format=json"))
            and "--test" in command and command[command.index("--test") + 1] == target,
            "unexpected release probe build command")
    require(not environment.get("LLVM_PROFILE_FILE") and not environment.get("NODE_V8_COVERAGE"),
            "fault probes cannot share unit coverage outputs")
    raw = Path(stdout).read_bytes()
    require(raw and raw.endswith(b"\n"), "Cargo output is not closed JSONL")
    records = [json.loads(line) for line in raw.decode().splitlines()]
    require(all(isinstance(row, dict) for row in records), "Cargo JSONL record is not an object")
    require(records[-1].get("reason") == "build-finished" and records[-1].get("success") is True,
            "Cargo did not finish successfully")
    artifact = one(records, lambda row: row.get("reason") == "compiler-artifact"
                   and row.get("target", {}).get("name") == target and row.get("executable"), "probe executable")
    require(artifact["target"]["kind"] == ["test"], "selected artifact is not a test")
    release_profile(artifact, True)
    native_artifact = one(records, lambda row: row.get("reason") == "compiler-artifact"
                          and row.get("target", {}).get("name") == "librocksdb_sys"
                          and row.get("package_id") == ROCKSDB_PACKAGE, "pinned native Rust binding")
    release_profile(native_artifact, False)
    native_script = one(records, lambda row: row.get("reason") == "build-script-executed"
                        and row.get("package_id") == ROCKSDB_PACKAGE, "native build script")
    require("static=rocksdb" in native_script["linked_libs"], "RocksDB is not statically linked")
    directories = [Path(value.removeprefix("native=")) for value in native_script["linked_paths"]
                   if value.startswith("native=")]
    libraries = [path / "librocksdb.a" for path in directories if (path / "librocksdb.a").is_file()]
    require(len(libraries) == 1, "expected one linked static RocksDB library")
    native_library = identity(libraries[0])
    selected = external_native(environment)
    if selected is None:
        require(Path(native_library["path"]).parent == Path(native_script["out_dir"]).resolve(),
                "source-built RocksDB must come from its actual Cargo build-script output")
        basis = "cargo-release-native-build"
    else:
        require(selected == native_library and (native_before is None or native_before == selected),
                "external RocksDB input changed during compilation")
        basis = "externally-pinned-release-library"
    # Record compiler inputs rather than asserting that an arbitrary external
    # library's machine code reveals its original optimization flags.
    native = {"profile": "release", "profile_basis": basis, "library": native_library,
              "expected_sha256": environment.get("SCAP_CONTROL_NATIVE_SHA256"),
              "cargo_artifact": native_artifact, "build_script": native_script,
              "cxxflags": environment.get("CXXFLAGS")}
    compiled = identity(artifact["executable"])
    copied = identity(executable)
    require((compiled["sha256"], compiled["bytes"]) == (copied["sha256"], copied["bytes"]),
            "copied probe differs from the actual Cargo executable")
    return {"schema": 1, "complete": True, "build_profile": "release", "target": target,
            "command": command, "cargo_artifact": artifact, "compiled_executable": compiled,
            "executable": copied, "native": native,
            "build_stdout": identity(stdout), "build_stderr": identity(stderr),
            "fault_tests_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-json", type=Path, required=True)
    parser.add_argument("--cargo-stderr", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--target", choices=("contracts", "legacy"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    receipt = record(args.cargo_json, args.cargo_stderr, args.executable, args.target, command)
    with args.output.open("x") as stream:
        stream.write(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"receipt": str(args.output.resolve()), "target": args.target,
                      "profile": receipt["build_profile"], "executable": receipt["executable"]}))


if __name__ == "__main__":
    main()
