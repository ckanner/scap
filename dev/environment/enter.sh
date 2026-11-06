#!/usr/bin/env bash
# Dependency changes require re-preparation. Rust source-only changes can use
# the same offline environment, but still require fresh database acceptance.
set -euo pipefail
prefix=${SCAP_ENV_PREFIX:-/opt/scap}
bootstrap=${SCAP_BOOTSTRAP:-/usr/local/lib/scap-environment/bootstrap.py}
repo=${SCAP_REPO:-/work}
check_root=$(mktemp -d "${TMPDIR:-/tmp}/scap-environment-check.XXXXXXXX")
# Commands owns a fresh child path; mktemp already created check_root.
evidence="$check_root/check"
python3 "$bootstrap" check \
  --repo "$repo" --prefix "$prefix" --evidence "$evidence"
export PATH="$prefix/cargo/bin:$prefix/python/bin:$prefix/bin:$PATH"
export RUSTUP_HOME="$prefix/rustup"
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
export CARGO_BUILD_JOBS=2 CXXFLAGS=-g0 CARGO_NET_OFFLINE=true RUSTUP_NO_UPDATE_CHECK=1
# Do not require root write access to the image's installation.
export CARGO_HOME
CARGO_HOME=$(mktemp -d "${TMPDIR:-/tmp}/scap-offline-cargo.XXXXXXXX")
cp "$prefix/cargo/config.toml" "$CARGO_HOME/config.toml"
unset RUSTUP_TOOLCHAIN RUSTUP_DIST_SERVER RUSTUP_UPDATE_ROOT
unset RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS LLVM_PROFILE_FILE PYTHONPATH
cd "$repo"
exec "$@"
