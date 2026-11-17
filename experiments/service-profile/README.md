# Actual-service diagnostic instrumentation

This is an opt-in profiling instrument for a disposable source copy. The ordinary
workspace does **not** depend on `scap-profile-metrics`, expose `/__profile`, or
replace its allocator. This experiment is separate from the frozen
`experiments/object-load` correctness/evidence contract.

The instrumented binary still runs the actual `scapd` entry point, bounded HTTP
transport, scheduler, engine, object protocol, signed S3 adapter, and pinned
native SQLite. `instrumentation.patch` adds counters at those existing
boundaries; it does not replace any implementation or remove validation. The
SDK probe uses the official Node client. Provisioning can reuse the existing
`Backend` in `experiments/object-network/run.py`; no new Python implementation is
part of this experiment.

## Build in an isolated source and target

1. Make a disposable worktree at the source being inspected. Retain its commit,
   all changed source hashes, Cargo.lock, Rust version, native archive hashes and
   the final executable hash before running it.
2. Check and apply `experiments/service-profile/instrumentation.patch`. Its
   recorded base is the PR60 object implementation plus the deadline-admission
   fix (`bb15999` in the local audit history). If context has changed, review an
   adaptation; do not silently apply mismatched hooks.
3. Build with a **new, unique target directory for each copied source**, including
   nonconcurrent comparisons. Cross-worktree target reuse has produced stale
   executables in this environment and is not an acceptable shortcut.

```sh
git apply --check experiments/service-profile/instrumentation.patch
git apply experiments/service-profile/instrumentation.patch
CARGO_TARGET_DIR=/absolute/path/profile-target-for-this-source \
  cargo +1.90.0 build --release --locked -p scap-service --bin scapd
```

The patch also adds the metrics crate to the temporary workspace and dependency
graph. Do not copy the modified Cargo files or instrumented production files
back into the normal product. The allocator/clock FFI is confined to the
diagnostic crate and is not a production exception to the unsafe-code policy.

## Fixed probe and observations

Start the instrumented executable on loopback with an ordinary validated SCAP
configuration, a fresh private cache, and a fresh signed local S3 namespace. The
recorded run uses Rust 1.90.0, Node 22.16.0, SeaweedFS 4.51, and the production
limits from `experiments/object-load/spec.py`. It connects directly to signed S3;
the object-load raw-evidence proxy is deliberately absent **only in this separate
diagnostic**. Do not compare its TPS with the original evidence-proxy TPS.

Supply a private client config with `endpoint`, `source_root`, and the configured
tenant tokens under `tokens["7"]` and `tokens["8"]`, then run:

```sh
node experiments/service-profile/probe.mjs client.private.json profile.json
```

The probe creates six databases at fixed scopes (tenant 7: 101, 102, 201, 202;
tenant 8: 301, 302). Their authorization principals are 11 and 22 respectively.
All namespace contents must be new for every run. Inputs are prepared before
each timed phase. A closed-loop lane issues each original execute once, with no
SQL retry. Four phases are fixed:

| Phase | Calls | Concurrency | Work |
|---|---:|---:|---|
| `write_seq` | 16 | 1 | One database; 4 KiB payload and original `RETURNING` result |
| `write_multi` | 64 | 4 | Four databases; one lane per database |
| `write_same` | 32 | 4 | Four lanes contending for one database actor |
| `read_multi` | 32 | 4 | Fresh-authorized warm count queries on four databases |

Each run records all 144 call outcomes/latencies, two counter snapshots per
phase, and request-body hashes. After measurement it checks all 112 original
write results by lookup, including the retained nondeterministic `random()`
witness, and every final row/payload in all six databases. Setup, lookup and
audit make 280 SDK POSTs in total. These checks do not replace the formal fault,
restart, GC, or AWS contracts.

## Interpret the counters correctly

`metrics/src/lib.rs` records inclusive wall time, current-thread CPU, Rust
allocation/reallocation attempts, requested allocation bytes, and successful
GET/attempted PUT body bytes. Stages are engine, S3 GET/PUT, native SQL, result
encoding/decoding, COMMIT, checkpoint, HEAD fingerprint/encoding/decoding,
immutable object encoding/validation, queue wait, and native publication after
the authority gate. Do not add overlapping stages: COMMIT contains publication
and most S3 calls; engine contains the whole operation. Four concurrent lanes
can accumulate more stage wall time than the elapsed phase.

Allocation bytes are cumulative requested capacities, including reallocations
and instrumentation overhead. They are **not** live heap, peak memory, RSS or
native SQLite malloc accounting. Thread CPU covers the caller, including work
polled there by the S3 runtime; process CPU includes all daemon threads. The
`Objects` counts are adapter invocations and body bytes, not packet/header bytes
or an independent raw wire transcript.

The counter-only tracing subscriber observes pinned Hyper-util 0.1.21 events:
`connect/http.rs` lines 786/789 (connect start/completion), and `pool.rs` line 267
(idle checkout). It never formats request headers or credentials. Preserve the
source hashes of these exact files. On a different dependency version, review
the event locations first. Connect races can create unused sockets, so successful
connects plus checkout events need not equal request count.

No timing is meaningful while another agent is building, running native tests,
or using a competing backend. Obtain affirmative quiet confirmations from all
workers, await each owned process and backend teardown before starting the next
sample, retain every failure/overlap, and label exclusions. The 2026-11-17 record
includes both an unavailable ptrace attempt and overlapped runs; they are not
silently removed.

The full interpretation and source identities are in
`docs/engineering/service-hot-path-profile-2026-11-17.md` and
`docs/evidence/service-hot-path-profile-local-2026-11-17.json`.
