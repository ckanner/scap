#!/usr/bin/env bash
# Full local acceptance entrypoint; stop on the first actual failure.
# It does NOT merge, retry failed database operations, or change Git refs.
set -euo pipefail
: "${SCAP_EVIDENCE:?Set an unused absolute evidence directory outside the source checkout}"
# The packaged image uses /opt/scap; an equivalent already-installed local
# toolchain may provide explicit executables without fabricating READY metadata.
SCAP_PYTHON=${SCAP_PYTHON:-/opt/scap/python/bin/python}
SCAP_WEED=${SCAP_WEED:-/opt/scap/bin/weed}
repo=$(git rev-parse --show-toplevel)
case "$SCAP_EVIDENCE" in /*) ;; *) echo 'SCAP_EVIDENCE must be absolute' >&2; exit 2 ;; esac
python3 - "$repo" "$SCAP_EVIDENCE" <<'CHECK_PATH'
import pathlib, sys
repo, evidence = map(lambda value: pathlib.Path(value).resolve(), sys.argv[1:])
if evidence == repo or evidence.is_relative_to(repo):
    raise SystemExit("SCAP_EVIDENCE must be outside the source checkout")
CHECK_PATH
mkdir "$SCAP_EVIDENCE"
python3 "$repo/scripts/source_manifest.py" capture "$SCAP_EVIDENCE/source-before.json"
finish() {
  code=$?
  trap - EXIT
  if ! python3 "$repo/scripts/source_manifest.py" verify "$SCAP_EVIDENCE/source-before.json" \
       > "$SCAP_EVIDENCE/source-verify.log" 2>&1; then code=1; fi
  printf '{"exit_code":%d,"aws_standard":"NOT_RUN","production_slo_passed":false}\n' \
      "$code" > "$SCAP_EVIDENCE/completion.json"
  exit "$code"
}
trap finish EXIT
unset LLVM_PROFILE_FILE RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
unset NODE_OPTIONS NODE_PATH NODE_V8_COVERAGE
# Validate the evidence boundary first, then record missing/wrong tools as a
# failed run. A missing executable must not make path-boundary tests pass.
"$SCAP_PYTHON" -c 'import coverage; assert coverage.__version__ == "7.10.6"; print(coverage.__version__)' \
  2>&1 | tee "$SCAP_EVIDENCE/coverage-version.log"
"$SCAP_WEED" version 2>&1 | tee "$SCAP_EVIDENCE/weed-version.log" \
  | grep -F '4.51 153ab668c99731a6d29492bf6c61d0b4fa701101'
node --version 2>&1 | tee "$SCAP_EVIDENCE/node-version.log" | grep -Fx 'v22.16.0'
npm --version 2>&1 | tee "$SCAP_EVIDENCE/npm-version.log" | grep -Fx '10.9.2'
# Each acceptance invocation owns its build outputs. A concurrent run of a
# different checkout must never replace the worker after its receipt is saved.
# Separate coverage from stable/native profiles, and service from worker links.
mkdir -p "$repo/target"
target_root=$(mktemp -d "$repo/target/acceptance.XXXXXXXX")
printf '%s\n' "$target_root" > "$SCAP_EVIDENCE/target-directory.txt"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$target_root/stable-unit"
export COVERAGE_FILE="$SCAP_EVIDENCE/tooling.coverage"
cargo +1.90.0 fmt --all -- --check 2>&1 | tee "$SCAP_EVIDENCE/format.log"
cargo +1.90.0 clippy --workspace --all-targets --all-features --frozen -- -D warnings 2>&1 | tee "$SCAP_EVIDENCE/clippy.log"
cargo +1.90.0 test --workspace --lib --bins --all-features --frozen -- --test-threads=1 \
  2>&1 | tee "$SCAP_EVIDENCE/stable-unit.log"
export CARGO_TARGET_DIR="$target_root/coverage-unit"
cargo +nightly-2025-09-18 llvm-cov --workspace --lib --bins --all-features --frozen \
  --branch --no-cfg-coverage --no-cfg-coverage-nightly --json \
  --output-path "$SCAP_EVIDENCE/unit.json" -- --test-threads=1 2>&1 | tee "$SCAP_EVIDENCE/unit.log"
python3 scripts/check_unit_coverage.py "$SCAP_EVIDENCE/unit.json" 2>&1 | tee "$SCAP_EVIDENCE/unit-counters.log"
"$SCAP_PYTHON" -m coverage erase
"$SCAP_PYTHON" -m coverage run --branch --source=scripts -m unittest discover -s tests/tooling 2>&1 | tee "$SCAP_EVIDENCE/tooling.log"
"$SCAP_PYTHON" -m coverage report --show-missing --fail-under=100 2>&1 | tee "$SCAP_EVIDENCE/tooling-counters.log"
"$SCAP_PYTHON" -m coverage json -o "$SCAP_EVIDENCE/tooling.json"
NODE_V8_COVERAGE="$SCAP_EVIDENCE/node-codec-v8" npm --prefix sdk/node-codec test 2>&1 | tee "$SCAP_EVIDENCE/node-codec.log"
NODE_V8_COVERAGE="$SCAP_EVIDENCE/node-sdk-v8" npm --prefix sdk/node test 2>&1 | tee "$SCAP_EVIDENCE/node-sdk.log"
npm --prefix sdk/node run test:http 2>&1 | tee "$SCAP_EVIDENCE/node-sdk-http.log"
python3 scripts/check_repo.py 2>&1 | tee "$SCAP_EVIDENCE/repo.log"
python3 -m unittest discover -s experiments/object-authority-model -p 'test_*.py' -v 2>&1 | tee "$SCAP_EVIDENCE/model-unit.log"
python3 experiments/object-authority-model/explore.py --output "$SCAP_EVIDENCE/model"
python3 -m unittest discover -s experiments/object-network -p 'test_*.py' -v 2>&1 | tee "$SCAP_EVIDENCE/fixture-tests.log"
python3 -m unittest discover -s experiments/object-service -p 'test_*.py' -v \
  2>&1 | tee "$SCAP_EVIDENCE/service-fixture-tests.log"
unset LLVM_PROFILE_FILE RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export CARGO_TARGET_DIR="$target_root/network-release"
cargo +1.90.0 fmt --manifest-path experiments/object-network/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/object-network/Cargo.toml --all-targets --frozen -- -D warnings
python3 experiments/object-network/build.py --target-dir "$CARGO_TARGET_DIR" --evidence "$SCAP_EVIDENCE/build"
worker="$CARGO_TARGET_DIR/release/scap-object-network"
record="$SCAP_EVIDENCE/build/build.json"
python3 experiments/object-network/run.py --worker "$worker" --weed "$SCAP_WEED" \
  --build-record "$record" --evidence "$SCAP_EVIDENCE/network"
python3 experiments/object-network/retained_result_contract.py --worker "$worker" --weed "$SCAP_WEED" \
  --build-record "$record" --evidence "$SCAP_EVIDENCE/result-integrity"
python3 experiments/object-capacity/run.py --worker "$worker" --weed "$SCAP_WEED" \
  --build-record "$record" --profile gib1 --evidence "$SCAP_EVIDENCE/gib1"
python3 experiments/object-network/lifecycle_contract.py --worker "$worker" --weed "$SCAP_WEED" \
  --build-record "$record" --evidence "$SCAP_EVIDENCE/lifecycle"
export CARGO_TARGET_DIR="$target_root/service-release"
python3 experiments/object-service/build.py --target-dir "$CARGO_TARGET_DIR" --evidence "$SCAP_EVIDENCE/service-build"
python3 experiments/object-service/run.py --server "$CARGO_TARGET_DIR/release/scapd" --weed "$SCAP_WEED" \
  --build-record "$SCAP_EVIDENCE/service-build/build.json" --evidence "$SCAP_EVIDENCE/service"
