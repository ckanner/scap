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
export CARGO_INCREMENTAL=0
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
python3 experiments/object-authority-model/named_catalogue_model.py --output "$SCAP_EVIDENCE/catalogue-model"
python3 -m unittest discover -s experiments/object-reclamation-model -p 'test_*.py' -v \
  2>&1 | tee "$SCAP_EVIDENCE/reclamation-unit.log"
# Finite independent model only. A truncated graph is a failing gate, and this
# does not enable production HEAD5, pins, DELETE, or claim actual S3 execution.
python3 experiments/object-reclamation-model/run.py --output "$SCAP_EVIDENCE/reclamation-graph"
python3 experiments/object-reclamation-model/oracle.py --evidence "$SCAP_EVIDENCE/reclamation-graph" \
  --output "$SCAP_EVIDENCE/reclamation-oracle"
python3 experiments/object-reclamation-model/controls.py --evidence "$SCAP_EVIDENCE/reclamation-graph" \
  --output "$SCAP_EVIDENCE/reclamation-controls"
python3 -m unittest discover -s experiments/object-network -p 'test_*.py' -v 2>&1 | tee "$SCAP_EVIDENCE/fixture-tests.log"
python3 -m unittest discover -s experiments/object-service -p 'test_*.py' -v \
  2>&1 | tee "$SCAP_EVIDENCE/service-fixture-tests.log"
python3 -m unittest discover -s experiments/object-discovery -p 'test_*.py' -v \
  2>&1 | tee "$SCAP_EVIDENCE/discovery-fixture-tests.log"
python3 -m unittest discover -s experiments/object-gc-store -p 'test_*.py' -v \
  2>&1 | tee "$SCAP_EVIDENCE/gc-fixture-tests.log"
python3 -m unittest discover -s experiments/resource-limits -p 'test_*.py' -v \
  2>&1 | tee "$SCAP_EVIDENCE/resource-fixture-tests.log"
python3 -m unittest discover -s experiments/bounded-transport -p 'test_*.py' -v \
  2>&1 | tee "$SCAP_EVIDENCE/transport-fixture-tests.log"
unset LLVM_PROFILE_FILE RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export CARGO_TARGET_DIR="$target_root/network-release"
cargo +1.90.0 fmt --manifest-path experiments/object-network/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/object-network/Cargo.toml --all-targets --frozen -- -D warnings
cargo +1.90.0 fmt --manifest-path experiments/object-discovery/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/object-discovery/Cargo.toml --all-targets --frozen -- -D warnings
python3 experiments/object-network/build.py --target-dir "$CARGO_TARGET_DIR" --evidence "$SCAP_EVIDENCE/build"
python3 experiments/object-network/listing_build.py --target-dir "$CARGO_TARGET_DIR" --release \
  --evidence "$SCAP_EVIDENCE/listing-build"
python3 experiments/object-network/listing_contract.py \
  --worker "$CARGO_TARGET_DIR/release/examples/scap-object-listing" --weed "$SCAP_WEED" \
  --build-receipt "$SCAP_EVIDENCE/listing-build/build.json" --evidence "$SCAP_EVIDENCE/listing"
python3 experiments/object-network/response_contract.py \
  --worker "$CARGO_TARGET_DIR/release/examples/scap-object-listing" --weed "$SCAP_WEED" \
  --build-receipt "$SCAP_EVIDENCE/listing-build/build.json" --bounded --evidence "$SCAP_EVIDENCE/response-bounds"
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
python3 experiments/object-network/catalogue_contract.py --worker "$worker" --weed "$SCAP_WEED" \
  --build-record "$record" --evidence "$SCAP_EVIDENCE/catalogue"
python3 experiments/object-discovery/discovery_build.py --target-dir "$CARGO_TARGET_DIR" \
  --evidence "$SCAP_EVIDENCE/discovery-build"
python3 experiments/object-discovery/discovery_contract.py \
  --seed-worker "$worker" --seed-build "$record" \
  --worker "$CARGO_TARGET_DIR/release/scap-object-discovery" \
  --build "$SCAP_EVIDENCE/discovery-build/build.json" --weed "$SCAP_WEED" \
  --evidence "$SCAP_EVIDENCE/deployment-recovery"
python3 experiments/object-discovery/discovery_oracle.py \
  --evidence "$SCAP_EVIDENCE/deployment-recovery" > "$SCAP_EVIDENCE/deployment-recovery-oracle.json"
python3 experiments/object-discovery/discovery_controls.py \
  --evidence "$SCAP_EVIDENCE/deployment-recovery" > "$SCAP_EVIDENCE/deployment-recovery-controls.json"
export CARGO_TARGET_DIR="$target_root/service-release"
python3 experiments/object-service/build.py --target-dir "$CARGO_TARGET_DIR" --evidence "$SCAP_EVIDENCE/service-build"
python3 experiments/object-service/run.py --server "$CARGO_TARGET_DIR/release/scapd" --weed "$SCAP_WEED" \
  --build-record "$SCAP_EVIDENCE/service-build/build.json" --evidence "$SCAP_EVIDENCE/service"
python3 experiments/bounded-transport/run.py --binary "$CARGO_TARGET_DIR/release/scapd" \
  --evidence "$SCAP_EVIDENCE/bounded-transport"
python3 experiments/bounded-transport/oracle.py "$SCAP_EVIDENCE/bounded-transport/observations.json" \
  > "$SCAP_EVIDENCE/bounded-transport-oracle.json"
python3 experiments/object-service/owner_contract.py --server "$CARGO_TARGET_DIR/release/scapd" --weed "$SCAP_WEED" \
  --build-record "$SCAP_EVIDENCE/service-build/build.json" --evidence "$SCAP_EVIDENCE/owner"
python3 experiments/object-service/owner_oracle.py --evidence "$SCAP_EVIDENCE/owner" \
  > "$SCAP_EVIDENCE/owner-oracle.json"
python3 experiments/object-service/owner_controls.py --evidence "$SCAP_EVIDENCE/owner" \
  --output "$SCAP_EVIDENCE/owner-controls"
python3 experiments/object-service/catalogue_contract.py --server "$CARGO_TARGET_DIR/release/scapd" --weed "$SCAP_WEED" \
  --build-record "$SCAP_EVIDENCE/service-build/build.json" --evidence "$SCAP_EVIDENCE/catalogue-service"
python3 experiments/object-service/isolation_contract.py --server "$CARGO_TARGET_DIR/release/scapd" --weed "$SCAP_WEED" \
  --build-record "$SCAP_EVIDENCE/service-build/build.json" --evidence "$SCAP_EVIDENCE/isolation-service"
python3 experiments/object-service/isolation_controls.py --evidence "$SCAP_EVIDENCE/isolation-service" \
  --output "$SCAP_EVIDENCE/isolation-controls"
python3 experiments/object-service/segmented_contract.py --server "$CARGO_TARGET_DIR/release/scapd" --weed "$SCAP_WEED" \
  --build-record "$SCAP_EVIDENCE/service-build/build.json" --evidence "$SCAP_EVIDENCE/segmented-service"
python3 experiments/object-service/segmented_oracle.py "$SCAP_EVIDENCE/segmented-service" \
  > "$SCAP_EVIDENCE/segmented-oracle.json"
python3 experiments/object-service/segmented_controls.py --evidence "$SCAP_EVIDENCE/segmented-service" \
  --output "$SCAP_EVIDENCE/segmented-controls"
python3 experiments/object-service/discovery_contract.py --server "$CARGO_TARGET_DIR/release/scapd" --weed "$SCAP_WEED" \
  --build-record "$SCAP_EVIDENCE/service-build/build.json" --evidence "$SCAP_EVIDENCE/discovery-service"
export CARGO_TARGET_DIR="$target_root/resource-check"
cargo +1.90.0 fmt --manifest-path experiments/object-gc-store/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/object-gc-store/Cargo.toml --all-targets --frozen -- -D warnings
cargo +1.90.0 fmt --manifest-path experiments/resource-limits/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/resource-limits/Cargo.toml --all-targets --frozen -- -D warnings
# These builders require unused output directories outside the source checkout.
python3 experiments/object-gc-store/build.py --target "$SCAP_EVIDENCE/gc-target" \
  --evidence "$SCAP_EVIDENCE/gc-build"
python3 experiments/object-gc-store/run.py --worker "$SCAP_EVIDENCE/gc-target/release/scap-object-gc-store" \
  --build-receipt "$SCAP_EVIDENCE/gc-build/build.json" --weed "$SCAP_WEED" \
  --evidence "$SCAP_EVIDENCE/gc-store"
python3 experiments/resource-limits/build.py --target "$SCAP_EVIDENCE/resource-target" \
  --evidence "$SCAP_EVIDENCE/resource-build"
python3 experiments/resource-limits/run.py --worker "$SCAP_EVIDENCE/resource-target/release/scap-resource-limits" \
  --build "$SCAP_EVIDENCE/resource-build/build.json" --weed "$SCAP_WEED" \
  --evidence "$SCAP_EVIDENCE/resource-limits"
python3 experiments/resource-limits/oracle.py "$SCAP_EVIDENCE/resource-limits" \
  > "$SCAP_EVIDENCE/resource-oracle.json"
python3 experiments/resource-limits/controls.py "$SCAP_EVIDENCE/resource-limits" \
  > "$SCAP_EVIDENCE/resource-controls.json"
