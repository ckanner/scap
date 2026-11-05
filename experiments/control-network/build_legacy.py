"""Build the trusted fixture producer against an exact archived v4 git tree.

The archive is a separate private source directory; the candidate and the old
repository are read-only inputs. The receipt binds source, harness, command,
closed build output, and the independently hashed produced executable.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from record_probe_build import external_native, record as record_probe_build

DEFAULT_COMMIT = "f14b03d03d9216ea56b78aef9d71c5d78fd83645"
KNOWN_TREES = {
    DEFAULT_COMMIT: "43131a1599d2e20b4865025e2040a0796ee9cd80",
    "99e1e31cab1fd23fa25a64211671f9ceb56d8058": "43131a1599d2e20b4865025e2040a0796ee9cd80",
    "fa34c955ab8bcb1895e1348184bd0687d07833f8": "769f3f2491a7731bc4bab86961e6a6ff79a20046",
}


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(path):
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}


def source_files(directory):
    return [path for path in sorted(directory.rglob("*")) if path.is_file()
            and "target" not in path.parts and "__pycache__" not in path.parts]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--commit", default=DEFAULT_COMMIT, choices=sorted(KNOWN_TREES))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    output = args.output or Path(tempfile.mkdtemp(prefix="scap-control-legacy-build-"))
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit("output must be a new, empty private build directory")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    tree = subprocess.check_output(["git", "-C", str(args.repository), "rev-parse", args.commit + "^{tree}"], text=True).strip()
    if tree != KNOWN_TREES[args.commit]:
        raise SystemExit("old source commit does not match the pinned exact tree")
    archive = output / "source.tar"
    with archive.open("wb") as target:
        subprocess.run(["git", "-C", str(args.repository), "archive", "--format=tar", args.commit], stdout=target, check=True)
    source = output / "source"
    source.mkdir(mode=0o700)
    with tarfile.open(archive) as data:
        data.extractall(source, filter="data")
    candidate = Path(__file__).resolve().parent
    destination = source / "experiments" / "control-network"
    destination.mkdir(mode=0o700)
    inputs = []
    compiled_harness = {"Cargo.toml", "Cargo.lock", "src/common.rs", "src/harness.rs", "src/legacy_child.rs", "tests/legacy.rs"}
    for filename in source_files(candidate):
        relative = filename.relative_to(candidate)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(filename, target)
        if relative.as_posix() in compiled_harness:
            inputs.append({"relative_path": relative.as_posix(), **identity(filename)})
    # The legacy test uses only its own old-compatible child, common/harness,
    # and unchanged sqlite-network fixture modules from this exact git archive.
    production_inputs = [identity(path) for path in source_files(source / "crates")]
    production_inputs += [identity(path) for path in source_files(source / "experiments" / "sqlite-network" / "src")]
    command = [args.cargo, "+1.90.0", "test", "--release", "--offline", "--locked", "--manifest-path", str(destination / "Cargo.toml"),
               "--test", "legacy", "--features", "legacy-producer", "--no-run", "--message-format=json"]
    environment = os.environ.copy()
    environment["SCAP_CONTROL_LEGACY_SOURCE_COMMIT"] = args.commit
    environment["SCAP_CONTROL_LEGACY_SOURCE_TREE"] = tree
    if environment.get("LLVM_PROFILE_FILE"):
        raise SystemExit("legacy fault producer must not share unit coverage environment")
    native_before = external_native(environment)
    stdout, stderr = output / "cargo.jsonl", output / "cargo.stderr.log"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        result = subprocess.run(command, env=environment, stdout=out, stderr=err, timeout=1800)
    if result.returncode:
        raise SystemExit(f"legacy build failed ({result.returncode}); original closed logs: {stderr}")
    executables = []
    for line in stdout.read_text().splitlines():
        record = json.loads(line)
        if record.get("reason") == "compiler-artifact" and record.get("target", {}).get("name") == "legacy" and record.get("executable"):
            executables.append(Path(record["executable"]))
    if len(executables) != 1:
        raise SystemExit("expected one exact legacy test executable")
    for item in inputs:
        if sha(Path(item["path"])) != item["sha256"] or sha(destination / item["relative_path"]) != item["sha256"]:
            raise SystemExit("harness inputs changed during compilation")
    for item in production_inputs:
        if sha(Path(item["path"])) != item["sha256"]:
            raise SystemExit("archived first-party inputs changed during compilation")
    # Keep an immutable copy: rebuilding another source in a shared target may
    # later replace an executable with the same Cargo artifact name.
    executable = output / "legacy-control-producer"
    shutil.copyfile(executables[0], executable)
    executable.chmod(0o700)
    probe_build = record_probe_build(stdout, stderr, executable, "legacy", command,
                                    environment, native_before)
    receipt = {
        "schema": 1, "complete": True, "source_commit": args.commit, "source_tree": tree,
        "source_archive": identity(archive), "harness_inputs": inputs, "production_inputs": production_inputs,
        "command": command, "exit_code": result.returncode,
        "toolchain": subprocess.check_output([args.cargo, "+1.90.0", "--version"], text=True).strip(),
        "build_stdout": identity(stdout), "build_stderr": identity(stderr),
        "executable": identity(executable), "synthetic_old_state": False,
        "frozen_daemon_is_separate_binary": True,
        "probe_build": probe_build,
    }
    receipt_path = output / "legacy-source.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"executable": str(executable), "receipt": str(receipt_path), "source_commit": args.commit, "source_tree": tree}))


if __name__ == "__main__":
    main()
