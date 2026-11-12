# Actual production controller policy matrix

The [frozen PLAN](PLAN.md) defines twelve isolated real CLI histories for
first-winner concurrency, foreign policies/creators, manual markers, abort and
restart, current authorization, target guards, resource classification, deadlines
and shutdown. Each includes original nondeterministic SQL results and an S1 point.
This extends the existing single [controller runtime](../object-controller-runtime/README.md)
history; it does not implement S2 restore or certify a production deployment.

Use a clean source tree and the verified uninstrumented service release. The
runner independently verifies all receipt inputs against the current source.
Do not run a performance-sensitive capacity/latency fixture concurrently.

```sh
python experiments/object-controller-matrix/run.py \
  --server /absolute/path/to/scapd \
  --build-record /absolute/path/to/service-build/build.json \
  --weed /absolute/path/to/weed \
  --node /absolute/path/to/node \
  --evidence /absolute/path/outside/source/controller-matrix-actual

python experiments/object-controller-matrix/oracle.py \
  /absolute/path/outside/source/controller-matrix-actual
python experiments/object-controller-matrix/controls.py \
  /absolute/path/outside/source/controller-matrix-actual \
  --output /absolute/path/outside/source/controller-matrix-controls
```

`--case C1_same_policy_prepare_restart` selects a diagnostic case and explicitly
marks the root manifest incomplete. A complete verdict requires all twelve cases
on one frozen source, followed by the separate oracle and its targeted controls.
The runner writes only `OBSERVED_NOT_AUDITED` or `FAILED`; it cannot certify itself.
The controls use 28 fixed targeted contradictions and require the intended
rejection guard. Original evidence is read-only; negative copies go into the
new output directory, with inventory equality checked before and after.

The fixture has twenty self-checks: eighteen independent auditor tests and two
real HTTP loopback tests. They cover original conditional GET/CAS binding,
three independent failure observations, fresh post-cut reports, immutable raw
bytes, complete inventories, current owner observations, HTTP error status and
the full policy commitment. The loopbacks exercise atomically prearmed holds,
loss of only one genuine response, and a status socket cut without backend
forwarding. These test the observing/auditing helpers, not database policy:

```sh
python -m unittest discover -s experiments/object-controller-matrix -p 'test_*.py' -v
```

Every case preserves its source archive, build receipt, exact parameters, raw
HTTP/S3 bodies, owned process identities, public configurations and real CLI
reports. Authentication tokens and live cache/backend directories are private
and removed after owned cleanup. Original failed observations are retained.

Cancellation and refusal cases intentionally finish inactive or with unchanged
authority. The final verification is read-only and checks current authority,
native query values, the three original request results and the retained point.
The matrix never activates a database merely to make a blocked case look useful.
