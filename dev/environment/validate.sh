#!/usr/bin/env bash
# Full local acceptance entrypoint; stop on the first actual failure.
# It does NOT merge, retry failed database operations, or change Git refs.
set -euo pipefail
: "${SCAP_EVIDENCE:?Set an unused absolute evidence directory outside the source checkout}"
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
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$repo/target/isolated-unit"
export COVERAGE_FILE="$SCAP_EVIDENCE/tooling.coverage"
cargo +1.90.0 fmt --all -- --check 2>&1 | tee "$SCAP_EVIDENCE/format.log"
cargo +1.90.0 clippy --workspace --all-targets --all-features --frozen -- -D warnings 2>&1 | tee "$SCAP_EVIDENCE/clippy.log"
cargo +nightly-2025-09-18 llvm-cov clean --workspace
cargo +nightly-2025-09-18 llvm-cov --workspace --lib --bins --all-features --frozen \
  --branch --no-cfg-coverage --no-cfg-coverage-nightly --json \
  --output-path "$SCAP_EVIDENCE/unit.json" -- --test-threads=1 2>&1 | tee "$SCAP_EVIDENCE/unit.log"
python3 scripts/check_unit_coverage.py "$SCAP_EVIDENCE/unit.json" 2>&1 | tee "$SCAP_EVIDENCE/unit-counters.log"
/opt/scap/python/bin/python -m coverage erase
/opt/scap/python/bin/python -m coverage run --branch --source=scripts -m unittest discover -s tests/tooling 2>&1 | tee "$SCAP_EVIDENCE/tooling.log"
/opt/scap/python/bin/python -m coverage report --show-missing --fail-under=100 2>&1 | tee "$SCAP_EVIDENCE/tooling-counters.log"
/opt/scap/python/bin/python -m coverage json -o "$SCAP_EVIDENCE/tooling.json"
python3 scripts/check_repo.py 2>&1 | tee "$SCAP_EVIDENCE/repo.log"
python3 -m unittest discover -s experiments/object-authority-model -p 'test_*.py' -v 2>&1 | tee "$SCAP_EVIDENCE/model-unit.log"
python3 experiments/object-authority-model/explore.py --output "$SCAP_EVIDENCE/model"
# Retained-result tests exist only on #23 (or an integrated candidate).
if [[ -f experiments/object-network/test_retained_result_contract.py ]]; then
  python3 -m unittest discover -s experiments/object-network -p 'test_*.py' -v 2>&1 | tee "$SCAP_EVIDENCE/fixture-tests.log"
fi
unset LLVM_PROFILE_FILE RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export CARGO_TARGET_DIR="$repo/target/isolated-release"
cargo +1.90.0 fmt --manifest-path experiments/object-network/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/object-network/Cargo.toml --all-targets --frozen -- -D warnings
python3 experiments/object-network/build.py --target-dir "$CARGO_TARGET_DIR" --evidence "$SCAP_EVIDENCE/build"
worker="$CARGO_TARGET_DIR/release/scap-object-network"
record="$SCAP_EVIDENCE/build/build.json"
python3 experiments/object-network/run.py --worker "$worker" --weed /opt/scap/bin/weed \
  --build-record "$record" --evidence "$SCAP_EVIDENCE/network"
if [[ -f experiments/object-network/retained_result_contract.py ]]; then
  python3 experiments/object-network/retained_result_contract.py --worker "$worker" --weed /opt/scap/bin/weed \
    --build-record "$record" --evidence "$SCAP_EVIDENCE/result-integrity"
fi
python3 experiments/object-capacity/run.py --worker "$worker" --weed /opt/scap/bin/weed \
  --build-record "$record" --profile gib1 --evidence "$SCAP_EVIDENCE/gib1"
