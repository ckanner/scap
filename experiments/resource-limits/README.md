# Resource intake at the HTTP/native/S3 boundary

This standalone research fixture assembles the production HTTP router, admission
pools, scheduler, native engine and signed S3 adapter. It uses a private
SeaweedFS 4.51 backend and actual TCP clients. It does not implement a database
protocol or expose a new production route.

The frozen workload contains 25 HTTP calls across two tenants. Each admission
class permits two requests globally and one per tenant. A second principal of
the first tenant is used for the same-tenant pressure probes, so principal
rotation cannot obtain a second tenant slot.

The three transport cases are:

1. Send one byte of a known request body and keep the upload incomplete. Verify
   that another principal of that tenant receives `429 BACKPRESSURE`, while the
   other tenant and the control admission class complete. Finish the original
   body and observe that its intake slot is restored.
2. Execute one SDK-prepared write with its original request identity. Pause its
   first exact HEAD GET before delegation using an explicit operator command.
   The production HTTP deadline expires while the actual scheduler worker is
   still paused. Consume the `503 UNKNOWN` response, then verify the same tenant
   remains refused while the other tenant and control calls complete. Release
   the original worker explicitly; its unchanged deadline is passed to the real
   S3 adapter. Wait for actual completion and restored intake. Look up and cancel
   that same request identity, verify the cancellation proof, and query the
   schema to establish that the original SQL effect is absent. The write is
   never replayed.
3. Request eight one-MiB BLOB values through a TCP socket with a bounded receive
   buffer. Read its response headers, hold the body unread, and perform the same
   tenant/control probes. Drain the original complete response, independently
   decode all values, and observe that the slot is restored.

The pause wrapper delegates every real object operation unchanged. A failed
20-second pause safeguard is rejected by the oracle; only the explicit release
is acceptable. No HTTP, scheduler, native or S3 deadline is extended. The slow
TCP case is supplemental evidence for transport retention; the production unit
test remains the direct proof that the final `Bytes` clone owns its lease.

## Run

Requirements match the repository's pinned environment: Rust 1.90.0, Node
22.16.0, Python 3, a C/C++ toolchain and libclang for the pinned libsql build,
and the SeaweedFS 4.51 executable. The Cargo dependency lock is separate from
the workspace lock. Run from the repository root. Evidence and target paths
must be new absolute directories outside the repository.

First commit and freeze the candidate, including this fixture. The build
refuses a dirty tree and records every tracked source file, the actual compiler
executables, Cargo JSON artifacts, final release binary and native static
archives. It uses a fresh release target and disables inherited Rust coverage
instrumentation and compiler wrappers.

```sh
python3 -m unittest discover -s experiments/resource-limits -p 'test_*.py' -v
cargo +1.90.0 fmt --manifest-path experiments/resource-limits/Cargo.toml --check
cargo +1.90.0 clippy --frozen --manifest-path experiments/resource-limits/Cargo.toml --all-targets -- -D warnings

python3 experiments/resource-limits/build.py \
  --target /absolute/resource-release-01 \
  --evidence /absolute/resource-build-01

python3 experiments/resource-limits/run.py \
  --worker /absolute/resource-release-01/release/scap-resource-limits \
  --weed /absolute/weed \
  --build /absolute/resource-build-01/build.json \
  --evidence /absolute/resource-observation-01

python3 experiments/resource-limits/oracle.py /absolute/resource-observation-01
python3 experiments/resource-limits/controls.py /absolute/resource-observation-01
```

`run.py` refuses any source or binary change since the recorded build. Every
HTTP input is saved before sending, and every original response is captured
with its full bytes and digest. Each input's credential digest is bound to the
actual configured tenant and principal without recording the credential.
Operator commands, pause entry/release, worker
entry/completion, intake observations and owned process identities are recorded
in `events.jsonl`. `history.jsonl` captures complete original S3 exchanges with
body/ETag/conditional-write linkage and nonsecret signing identities. A direct
unsigned read of the existing HEAD must receive 403. The six named workload
processes (SDK preparation, worker, and four backend components) must all have
their own kernel `wait4` completion records. Legacy backend readiness and
version probes are not included in that six-process count.

The independent `oracle.py` imports the frozen workload and the independent
wire parser, not the controller or product implementation. It audits the raw
denominator, original request identity and fingerprint, response values,
resource lifetimes, exact object version chains, source/native build artifacts
and cleanup. `controls.py` first accepts the original observation, then verifies
that fourteen altered copies are rejected, including separate result metadata
and BLOB payload mutations. It never edits the original
evidence. Each failed attempt needs its own preserved evidence directory.

## Scope of the result

A pass establishes the three specified intake ownership and tenant-isolation
cases on the recorded local native/TCP/S3 stack. It is not a measurement of
production throughput, a global RSS or SQL allocator cap, remote S3 latency,
AWS Standard conformance, or arbitrary workload fairness. AWS and production
SLO results remain `NOT_RUN`. This integration evidence does not contribute to
the repository's unit-only line/function/region/branch coverage gate.
