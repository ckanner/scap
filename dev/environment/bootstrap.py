#!/usr/bin/env python3
"""Prepare a private pinned SCAP toolchain or diagnose missing prerequisites.

This is build infrastructure, not database acceptance. Online preparation must
finish every compiler/native/offline smoke check before READY.json is written.
Docker save/load is the supported offline transfer: it preserves OS libraries
and the fixed prefix. Do not tar a venv and claim it is a portable toolchain.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import tomllib

RUST = "1.90.0"
NIGHTLY = "nightly-2025-09-18"
RUSTUP = "1.28.2"
LLVM_COV = "0.6.21"
COVERAGE = "7.10.6"
HOST = "x86_64-unknown-linux-gnu"
SEAWEED_VERSION = "4.51"
SEAWEED_SHA256 = "c03be37416a8ee672c77766e20b22a4e1430744c3af2668599a4b6eeaec14cee"
SKIP = {".git", "target", "vendor", "node_modules", ".venv", "__pycache__"}
TOOLS = ("cc", "c++", "make", "cmake", "git", "curl", "python3", "tar", "xz")
URLS = {
    "rustup": f"https://static.rust-lang.org/rustup/archive/{RUSTUP}/{HOST}/rustup-init",
    "seaweed": f"https://github.com/seaweedfs/seaweedfs/releases/download/{SEAWEED_VERSION}/linux_amd64.tar.gz",
}
LIBCLANG_PROBE = r'''
import ctypes, json, pathlib, sys
class Text(ctypes.Structure):
    _fields_ = [('data', ctypes.c_void_p), ('flags', ctypes.c_uint)]
p = pathlib.Path(sys.argv[1]) / 'libclang.so'
c = ctypes.CDLL(str(p))
c.clang_getClangVersion.restype = Text
c.clang_getCString.argtypes = [Text]
c.clang_getCString.restype = ctypes.c_char_p
c.clang_disposeString.argtypes = [Text]
s = c.clang_getClangVersion()
try:
    print(c.clang_getCString(s).decode())
finally:
    c.clang_disposeString(s)
'''


class Blocked(RuntimeError):
    """A missing prerequisite or failed stage; never a skipped success."""


def need(condition, message):
    if not condition:
        raise Blocked(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def exclusive_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def dependency_inputs(repo):
    repo = Path(repo).resolve()
    required = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                "experiments/object-network/Cargo.toml", "experiments/object-network/Cargo.lock")
    for name in required:
        need((repo / name).is_file(), "Incomplete checkout: " + name)
    for name in (".cargo/config", ".cargo/config.toml"):
        need(not (repo / name).exists(), "Custom Cargo source/wrapper configuration is not supported by this offline image: " + name)
    toolchain = tomllib.loads((repo / "rust-toolchain.toml").read_text())
    need(toolchain["toolchain"]["channel"] == RUST, "Unexpected pinned Rust toolchain")
    inventory = {}
    for directory, dirs, files in os.walk(repo, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP)
        for name in files:
            if name not in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}:
                continue
            path = Path(directory) / name
            need(not path.is_symlink(), "Dependency input cannot be a symlink")
            inventory[path.relative_to(repo).as_posix()] = sha(path)
    return dict(sorted(inventory.items()))


def isolated_environment(prefix, libclang):
    result = dict(os.environ)
    for name in list(result):
        if name in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "LLVM_PROFILE_FILE", "RUSTC",
                    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN", "RUSTUP_DIST_SERVER",
                    "RUSTUP_UPDATE_ROOT", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR", "PYTHONPATH"}:
            del result[name]
    result.update(CARGO_HOME=str(prefix / "cargo"), RUSTUP_HOME=str(prefix / "rustup"),
                  LIBCLANG_PATH=str(libclang), CARGO_BUILD_JOBS="2", CXXFLAGS="-g0",
                  RUSTUP_NO_UPDATE_CHECK="1", CARGO_TERM_COLOR="never")
    result["PATH"] = str(prefix / "cargo/bin") + os.pathsep + result.get("PATH", "")
    return result


class Commands:
    def __init__(self, logs):
        self.logs = Path(logs)
        self.logs.mkdir(parents=True, exist_ok=False)
        self.records = []

    def run(self, name, argv, *, env=None, cwd=None, timeout=1800):
        need(re.fullmatch(r"[a-z0-9-]+", name) is not None, "Invalid stage name")
        out, err = self.logs / (name + ".stdout"), self.logs / (name + ".stderr")
        record = {"stage": name, "argv": [str(x) for x in argv], "timeout_seconds": timeout}
        self.records.append(record)
        try:
            with out.open("xb") as stdout, err.open("xb") as stderr:
                process = subprocess.run([str(x) for x in argv], cwd=cwd, env=env,
                                         stdout=stdout, stderr=stderr, timeout=timeout, check=False)
            record["exit_code"] = process.returncode
            need(process.returncode == 0, f"Stage {name} failed (exit {process.returncode}); see {err}")
            return out.read_text()
        except (OSError, subprocess.TimeoutExpired) as error:
            record["error_type"] = type(error).__name__
            raise Blocked(f"Stage {name} could not complete: {error}") from error

    def download(self, name, url, destination):
        need(url.startswith("https://"), "Only HTTPS tool downloads are allowed")
        self.run(name, ["curl", "--fail", "--location", "--proto", "=https", "--tlsv1.2",
                        "--connect-timeout", "5", "--max-time", "180", "--silent", "--show-error",
                        "--output", destination, url], timeout=190)


def verify_download(path, checksum_file):
    text = Path(checksum_file).read_text().strip()
    match = re.fullmatch(r"([a-f0-9]{64})(?:[ \t]+[^\r\n]+)?", text)
    need(match is not None, "Malformed published SHA-256")
    need(sha(path) == match.group(1), "Downloaded installer SHA-256 mismatch")
    return match.group(1)


def extract_weed(archive, destination):
    need(sha(archive) == SEAWEED_SHA256, "SeaweedFS archive SHA-256 mismatch")
    with tarfile.open(archive, "r:gz") as source:
        matches = [m for m in source.getmembers() if m.name in ("weed", "./weed")]
        need(len(matches) == 1 and matches[0].isfile() and matches[0].size <= 512 * 1024 * 1024,
             "Expected one bounded regular weed executable")
        with source.extractfile(matches[0]) as stream, Path(destination).open("xb") as output:
            shutil.copyfileobj(stream, output)
    Path(destination).chmod(0o755)


def smoke(prefix, libclang, commands, env):
    stable = commands.run("stable-version", ["rustc", "+" + RUST, "-Vv"], env=env)
    need(stable.startswith("rustc " + RUST + " "), "Stable compiler version mismatch")
    nightly = commands.run("nightly-version", ["rustc", "+" + NIGHTLY, "-Vv"], env=env)
    need("nightly" in nightly and "host: " + HOST in nightly, "Nightly compiler host mismatch")
    llvm_cov = commands.run("llvm-cov-version", ["cargo", "+" + RUST, "llvm-cov", "--version"], env=env)
    need(re.search(r"(?<![0-9.])" + re.escape(LLVM_COV) + r"(?![0-9.])", llvm_cov), "cargo-llvm-cov version mismatch")
    python = prefix / "python/bin/python"
    coverage = commands.run("coverage-version", [python, "-m", "coverage", "--version"], env=env)
    need(re.search(r"(?<![0-9.])" + re.escape(COVERAGE) + r"(?![0-9.])", coverage), "Python coverage version mismatch")
    clang = commands.run("libclang-smoke", [sys.executable, "-c", LIBCLANG_PROBE, libclang], env=env)
    need(re.search(r"clang version 18\.", clang), "libclang 18 is required; no silent fallback")
    weed = commands.run("weed-version", [prefix / "bin/weed", "version"], env=env)
    need("4.51 153ab668c99731a6d29492bf6c61d0b4fa701101" in weed, "SeaweedFS version mismatch")
    project = prefix / "smoke"
    (project / "src").mkdir(parents=True)
    (project / "Cargo.toml").write_text('[package]\nname="scap-env-smoke"\nversion="0.0.0"\nedition="2021"\n[workspace]\n')
    (project / "src/lib.rs").write_text('pub fn add(a:u64,b:u64)->u64{a+b}\n#[cfg(test)] mod tests { #[test] fn runs(){assert_eq!(super::add(2,3),5);} }\n')
    isolated = env | {"CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(project / "target")}
    manifest = project / "Cargo.toml"
    commands.run("stable-smoke", ["cargo", "+" + RUST, "test", "--offline", "--manifest-path", manifest], env=isolated)
    report = project / "llvm.json"
    commands.run("llvm-smoke", ["cargo", "+" + NIGHTLY, "llvm-cov", "--offline", "--locked",
                                  "--manifest-path", manifest, "--branch", "--json", "--output-path", report], env=isolated)
    content = json.loads(report.read_text())
    need(bool(content.get("data")), "Missing LLVM smoke counters")
    return {"stable": stable.strip(), "nightly": nightly.strip(), "libclang": clang.strip(),
            "cargo_llvm_cov": llvm_cov.strip(), "coverage": coverage.strip(), "weed": weed.strip(),
            "scope": "Compiler/linker/native-library smoke only; NOT project acceptance"}


def prepare(repo, prefix, libclang, commands):
    repo, prefix, libclang = Path(repo).resolve(), Path(prefix).resolve(), Path(libclang).resolve()
    need(platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"},
         "This pinned environment requires Linux x86_64; use the supplied linux/amd64 Docker build")
    need(not prefix.is_relative_to(repo), "Environment prefix must be outside the source checkout")
    need(not prefix.exists(), "Use a new prefix; never overwrite a ready or failed environment")
    before = dependency_inputs(repo)
    need((libclang / "libclang.so").is_file(), "Install libclang-18-dev or supply its library directory")
    for program in TOOLS:
        need(shutil.which(program), "Missing host prerequisite: " + program)
    prefix.mkdir(parents=True)
    state = {"status": "installing", "project_validation": "NOT_RUN", "pinned_stable": RUST,
             "pinned_nightly": NIGHTLY, "prefix": str(prefix), "dependencies": before}
    env = isolated_environment(prefix, libclang)
    try:
        downloads = prefix / "downloads"; downloads.mkdir()
        installer, checksum = downloads / "rustup-init", downloads / "rustup-init.sha256"
        commands.download("download-rustup", URLS["rustup"], installer)
        commands.download("download-rustup-checksum", URLS["rustup"] + ".sha256", checksum)
        state["rustup_sha256"] = verify_download(installer, checksum)
        installer.chmod(0o700)
        commands.run("install-rustup", [installer, "-y", "--no-modify-path", "--profile", "minimal",
                                       "--default-toolchain", "none"], env=env)
        commands.run("install-stable", ["rustup", "toolchain", "install", RUST, "--profile", "minimal",
                                        "--component", "rustfmt", "--component", "clippy"], env=env)
        commands.run("install-nightly", ["rustup", "toolchain", "install", NIGHTLY, "--profile", "minimal",
                                         "--component", "llvm-tools-preview"], env=env)
        commands.run("install-llvm-cov", ["cargo", "+" + RUST, "install", "cargo-llvm-cov", "--version", LLVM_COV,
                                          "--locked"], env=env)
        commands.run("create-venv", [sys.executable, "-m", "venv", prefix / "python"], env=env)
        commands.run("install-coverage", [prefix / "python/bin/python", "-m", "pip", "install",
                                           "--disable-pip-version-check", "--only-binary=:all:", "--no-deps",
                                           "coverage==" + COVERAGE], env=env)
        archive = downloads / "weed.tar.gz"
        commands.download("download-seaweed", URLS["seaweed"], archive)
        (prefix / "bin").mkdir()
        extract_weed(archive, prefix / "bin/weed")
        vendor = ["cargo", "+" + RUST, "vendor", "--locked", "--versioned-dirs",
                  "--manifest-path", repo / "Cargo.toml"]
        for name in before:
            if name.endswith("/Cargo.lock"):
                vendor.extend(["--sync", repo / Path(name).with_name("Cargo.toml")])
        vendor.append(prefix / "vendor")
        config = commands.run("vendor-locked-dependencies", vendor, env=env, cwd=repo)
        parsed = tomllib.loads(config)
        need("source" in parsed, "cargo vendor did not produce source replacement configuration")
        (prefix / "cargo/config.toml").write_text(config)
        # Prove offline dependency resolution without the installer's warm
        # registry or Git caches, not merely with --offline over a warm cache.
        (prefix / "offline-cargo").mkdir()
        (prefix / "offline-cargo/config.toml").write_text(config)
        env["CARGO_HOME"] = str(prefix / "offline-cargo")
        for index, lock in enumerate(name for name in before if name == "Cargo.lock" or name.endswith("/Cargo.lock")):
            commands.run(f"offline-metadata-{index}", ["cargo", "+" + RUST, "metadata", "--frozen",
                         "--format-version", "1", "--manifest-path", repo / Path(lock).with_name("Cargo.toml")],
                         env=env | {"CARGO_NET_OFFLINE": "true"}, cwd=repo)
        # Compile and link the actual pinned native adapter with no registry or
        # Git cache. A standalone Rust hello-world does not prove libSQL's
        # build script or libclang/SQLite archive can be used offline.
        commands.run("native-compile-probe", ["cargo", "+" + RUST, "test", "--manifest-path", repo / "Cargo.toml",
                     "-p", "scap-object-sqlite", "--lib", "--all-features", "--frozen", "--no-run"],
                     env=env | {"CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(prefix / "native-probe-target")}, cwd=repo)
        state["native_probe_scope"] = "Pinned native adapter/test binary compiled and linked; tests NOT executed"
        state["smoke"] = smoke(prefix, libclang, commands, env)
        need(dependency_inputs(repo) == before, "Dependency inputs changed during preparation")
        state["status"] = "environment_ready"
        state["vendor_config_sha256"] = sha(prefix / "cargo/config.toml")
        state["libclang_path"] = str(libclang)
        state["commands"] = commands.records
        lines = ['# Generated only after environment smoke checks; not project validation.']
        for name in ("CARGO_HOME", "RUSTUP_HOME", "LIBCLANG_PATH", "CARGO_BUILD_JOBS", "CXXFLAGS", "PATH"):
            lines.append("export " + name + "=" + shlex.quote(env[name]))
        lines.append('export CARGO_NET_OFFLINE=true')
        (prefix / "env.sh").write_text("\n".join(lines) + "\n")
        # Publish readiness only after every required artifact exists. A failed
        # env.sh write must not leave a reusable READY marker behind.
        exclusive_json(prefix / "READY.json", state)
        return state
    except BaseException as error:
        state.update(status="blocked", error_type=type(error).__name__, error=str(error), commands=commands.records)
        exclusive_json(prefix / "BLOCKED.json", state)
        raise


def check_ready(repo, prefix):
    prefix = Path(prefix).resolve()
    need(not (prefix / "BLOCKED.json").exists(), "A blocked preparation cannot be reused")
    state = json.loads((prefix / "READY.json").read_text())
    need(state.get("status") == "environment_ready", "Environment was never certified ready")
    need(state["prefix"] == str(prefix), "Installed prefixes/venvs are not relocatable; use docker save/load")
    need(state["dependencies"] == dependency_inputs(repo), "Dependency manifests changed; rebuild the offline environment")
    need(state["vendor_config_sha256"] == sha(prefix / "cargo/config.toml"), "Offline source configuration changed")
    need(state["vendor_config_sha256"] == sha(prefix / "offline-cargo/config.toml"), "Offline runtime configuration changed")
    return state


def doctor(commands, libclang):
    items = {name: shutil.which(name) for name in (*TOOLS, "rustup", "rustc", "cargo", "docker")}
    report = {"status": "blocked", "system": platform.system(), "machine": platform.machine(),
              "tools": items, "native_smoke": {}, "network": [], "project_validation": "NOT_RUN"}
    for name, argv in (("cc", ["cc", "--version"]), ("cxx", ["c++", "--version"]),
                       ("libclang", [sys.executable, "-c", LIBCLANG_PROBE, libclang])):
        try:
            output = commands.run("host-" + name, argv, timeout=15)
            report["native_smoke"][name] = {"status": "available", "version": output.strip()}
        except Blocked as error:
            report["native_smoke"][name] = {"status": "blocked", "error": str(error)}
    for host, url in (("static.rust-lang.org", URLS["rustup"] + ".sha256"),
                      ("github.com", "https://github.com/"), ("index.crates.io", "https://index.crates.io/config.json")):
        row = {"host": host}
        try:
            commands.run("network-" + host.split(".")[0], ["curl", "--head", "--fail", "--silent", "--show-error",
                         "--connect-timeout", "3", "--max-time", "5", url], timeout=8)
            row["status"] = "reachable"
        except Blocked as error:
            row.update(status="blocked", error=str(error))
        report["network"].append(row)
    report["commands"] = commands.records
    report["note"] = "Doctor never certifies installation or database tests; use prepare and the separate validation gate."
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("doctor", "prepare", "check"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".local/share/scap-env")
    parser.add_argument("--libclang", type=Path, default=Path("/usr/lib/llvm-18/lib"))
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    commands = Commands(args.evidence)
    try:
        if args.action == "doctor":
            result = doctor(commands, args.libclang)
        elif args.action == "check":
            check_ready(args.repo, args.prefix)
            result = {"status": "environment_inputs_match", "project_validation": "NOT_RUN"}
        else:
            result = prepare(args.repo, args.prefix, args.libclang, commands)
        exclusive_json(commands.logs / "summary.json", result)
        print(json.dumps({"status": result["status"], "evidence": str(commands.logs)}))
        return 1 if result["status"] == "blocked" else 0
    except (Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result = {"status": "blocked", "error_type": type(error).__name__, "error": str(error),
                  "project_validation": "NOT_RUN", "commands": commands.records}
        exclusive_json(commands.logs / "summary.json", result)
        print(json.dumps(result))
        return 1


if __name__ == "__main__":
    sys.exit(main())
