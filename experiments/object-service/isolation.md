# Bounded actor isolation: real HTTP and signed S3 contract

This contract executes the actual release `scapd`, its statically linked native
SQLite, the public Node SDK, and SeaweedFS 4.51. It is separate from Rust unit
coverage. SeaweedFS is an S3 compatibility backend; this result is not an AWS
Standard/Express qualification or a production throughput measurement.

## Fixed scenario

One daemon has two database actor slots, two actor slots per tenant, one control
worker, one recovery permit, a 3-second actor idle timeout, and the explicit
bounded queues in [isolation_spec.py](isolation_spec.py). A and B are databases
in the same tenant. There is no parallel owner, automatic takeover, or SQL retry.

The SDK creates and activates A and B and executes one original transaction in
each. Each transaction stores a random BLOB, Unicode/NUL text, and a persisted
SQLite `random()` value, and returns their original complete values. A has a
384 KiB BLOB, so its SQLite image contains at least four 128 KiB-or-smaller data
chunks. Inputs are fsynced before execution; original raw responses are retained.

Six fixed B queries, each following a 750 ms delay, keep B resident while A's
3-second idle timeout expires. The controller gates the first data chunk GET of
A's original committed page tree when a new full `Open` reaches it. The gate
does not return a fake object or change an ETag. While that GET remains blocked,
the same daemon must finish B query, a C query rejected with `BACKPRESSURE`, A
`Status`, and another B query within a fixed 4-second process budget.

After the gate releases, A must finish its full Open. Its next query and B's
next query each perform exactly one fresh HEAD GET and no immutable-object GET.
Both original transaction lookups must return byte-for-byte original receipts
and results, including the persisted `random()` value. This demonstrates that
the completed recovery's resident Session is reused; thread confinement itself
is additionally checked by the scheduler's real call-gate/native unit tests.

The complete fixed denominator is 21 SDK/HTTP invocations: 20 successful HTTP
responses and one typed capacity refusal, 2 unique SQL inputs, 2 original commit
responses, 10 successful queries, and 2 original-result lookups. There are no
retries or omitted slow calls. The plan and complete deadlines are recorded
before starting the backend or daemon.

## Deadlines and evidence

The fixture uses the formal daemon configuration path: 15 seconds per S3
request, 20 seconds for recovery HTTP operations, and 25 seconds for the SDK
request. The proxy has a 12-second maximum hold and a 5-second arrival budget.
The complete hot/control client process must finish within 4 seconds of the
controller observing the blocked GET. It cannot pass by relying on the service
fixture's unrelated default 2-second S3 timeout.

[isolation_proxy.py](isolation_proxy.py) captures every original S3 request and
response body, digest, conditional header, opaque ETag, forwarding/delivery
event, and nonsecret SigV4 metadata. An additional unsigned GET of the exact
existing gated object must return an actual backend 403. Fixture credentials
remain private; Authorization bytes and access keys are never copied to public
evidence. Every SDK HTTP request and response is recorded as original bytes.

[isolation_oracle.py](isolation_oracle.py) imports no controller. It independently
decodes SQL fingerprints, SCAPRES1 results and typed SCAPOBJ2 frames, checks every
call against the fixed input denominator, binds each S3 exchange to its actual
HTTP interval/database, checks original GET body+ETag/CAS histories, walks the
entire committed page tree, and verifies immutable dependencies preceded the
original accepted HEAD. It checks all hot/control responses precede the gate
release, A's data GET is forwarded only after release, all A page-tree objects
are downloaded before Open returns, and both warm query paths are HEAD-only.

The oracle also checks original owned-child spawn/wait4 evidence, real process
lifetimes, exact daemon configuration bytes, original stdout/stderr hashes, the
actual executable/native archive bytes, archived source manifests, and raw
original Cargo release output. Controller success summaries are not authority.
Failed or incomplete runs keep their original evidence and private fixture;
they cannot be reclassified as passes by widening a deadline or reducing a
denominator. A corrected candidate uses a new build receipt and evidence folder.

## Commands

Run from the repository root with pinned Node 22.16.0, Rust 1.90.0, and the
SeaweedFS executable available. Use fresh evidence paths for every run.

```sh
python3 experiments/object-service/build.py \
  --target-dir /absolute/isolated-release \
  --evidence /absolute/isolation-build-evidence
python3 experiments/object-service/isolation_contract.py \
  --server /absolute/isolated-release/release/scapd \
  --weed /absolute/weed \
  --build-record /absolute/isolation-build-evidence/build.json \
  --evidence /absolute/isolation-evidence
python3 experiments/object-service/isolation_oracle.py /absolute/isolation-evidence
python3 experiments/object-service/isolation_controls.py \
  --evidence /absolute/isolation-evidence \
  --output /absolute/isolation-corruption-controls
python3 -m unittest discover -s experiments/object-service -p 'test_isolation*.py'
```

The fixture holds a small complete cold recovery; it does not measure a 10 GiB
restore deadline, fairness under CPU/disk/network saturation, single-database
multiwriter throughput, catalogue pagination, garbage collection, or PITR.
Those remain separate design/workload contracts. The actor/control/reaper
thread budget is documented in the architecture design; it is not a claim that
all process/runtime/catalogue/helper threads share that single limit.

The corruption-control command audits independent copies of the real evidence.
Its 21 negative controls reject changed deadlines, missing calls, modified
original results, warm-session data downloads, capacity refusals that touched
S3, missing cold chunks, early gate releases, wrong binaries/native archives,
missing kernel witnesses, altered raw Cargo output, and incomplete source
archives. A positive control changes the controller summary and still derives
the same verdict from original evidence. These controls are verifier tests;
they are not additional real HTTP/S3 workload executions or unit coverage.
