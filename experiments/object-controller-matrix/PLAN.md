# Frozen production owner-controller matrix

This contract closes the actual-policy gaps left by the single history in
[object-controller-runtime](../object-controller-runtime/PLAN.md). A passing
runtime report alone is not acceptance. The separate oracle must independently
check the original HTTP bodies, signed S3 traffic, fixed source and process
lifetimes, followed by independently targeted negative controls.

## Boundary and fixed inputs

The executable under test is `sdk/node/bin/owner-controller.mjs`, assembling the
real Node SDK controller, Fleet and owned HTTP transport. Its daemon is the
verified release `scapd`, with native SQLite and real SigV4-authenticated local
SeaweedFS 4.51. No controller, database state machine, response body or durable
decision is replaced by a model. Metadata and target route policy are fixed per
process. Transport observers may hold or close an original request/response;
they never construct a successful or error product response.

The complete denominator is exactly these twelve cases, in this order. Each
uses a new backend, Scope and private cache directories; database IDs are 8701
through 8712 in deployment 1, tenant 7, incarnation 1, generation 1. Expected
worker instances are A=9601, B=9602, C=9603, M=9605. Only the mismatch case really
runs worker 9604 behind the endpoint whose fixed policy expects B=9602.

| Case | Real history and required evidence | Correct final state |
| --- | --- | --- |
| `C1_same_policy_prepare_restart` | Two overlapping CLIs have byte-identical public policies. One actual B status socket cut makes the first CLI choose allowed C. Both original prepare calls are held before forwarding, with identical creator/S and different allowed targets. First C prepare wins; its genuine response is lost. The other prepare returns Conflict. Both issuers exit, then a fresh CLI adopts the durable original input/reference and activates C. | C Active, original first-winner reference |
| `C2_same_creator_policy` | Two live policies swap B/C ranks, deriving different complete four-nonce commitments. Same creator/S preparations compete. The first durable descriptor wins; the other call conflicts and its CLI later reports Policy. After winner activation, observe two further Policy reports and no later loser mutation or rank failback. | Winner B or C Active |
| `C2_different_creators` | Real principals 12 and 13 prepare at the same original S. Hold both original claim requests before forwarding, then release them in order. Only one accepted plan wins. After winner activation the loser observes ForeignCreator twice and makes no later mutation. | One original winner Active |
| `C2_manual_marker` | Explicit principal-11 manual setup prepares and claims B; these setup RPCs are marked and never counted as automatic decisions. Real CLI principal 12 observes ForeignCreator twice and sends no owner mutation. | Original manual Claimed, inactive |
| `C3_claimed_abort` | A real CLI automatically reaches Claimed; its original resume is held before forwarding. Actual B probe sockets close. A second real CLI meets the original target suspicion window and aborts that plan. Release the original resume after Aborted; it observes the original aborted plan without Active publication. | Aborted, inactive |
| `C3_cancelling_restart` | Hold an automatically issued original claim before forwarding. Actual B probes then fail. A second CLI adopts the prepared first winner and automatically aborts it; the genuine Cancelling response is lost. Join both old CLIs. A fresh CLI adopts Cancelling and aborts the same reference. Release the late original claim; it only observes Aborted. | Aborted, inactive |
| `C3_healthy_original` | A stays physically alive while its probe sockets close. Hold the genuine prepare response, restore A's route, then release that response. Two subsequent real healthy observations protect the original active owner and leave the first-winner descriptor unaccepted, with no claim/resume/abort. | A Active, descriptor Prepared |
| `C4_revoked_authority` | CLI first observes healthy A. Business principal 11 performs a real set-policy mutation removing principal 12. The CLI then observes two genuine Denied responses and performs no subsequent owner mutation. | A Active, principal 12 revoked |
| `C4_worker_mismatch` | A dies and loses its cache. After the fixed suspicion threshold, the endpoint configured as B really answers from worker 9604. Two genuine TargetMismatch responses block the controller; no owner preparation is allowed. | Original A authority unchanged |
| `C4_resource_refusal` | M's real control intake has one slot. A genuine principal-11 status occupies it while its signed HEAD GET is held; the CLI receives actual HTTP 429 Backpressure without owner mutation. Release that original read and observe fresh healthy state. Then kill A. B's real service configuration sets owner-recovery payload GET/byte budgets to zero. Automatic preparation/claim still occurs. Two actual resume calls return HTTP 413 Limit, produce waiting/backoff reports, and never publish Active. | Claimed, inactive |
| `C4_s3_unavailable` | A stays healthy. The preferred of two fixed metadata routes loses an actual signed HEAD GET before forwarding, producing real service HTTP 503 Unknown. The existing SDK maps that read response to UnknownError, so the controller reports Unknown without an owner mutation or a death-suspicion increment. An independent read through the other metadata route succeeds. A later fresh tick recovers healthy state. | A Active |
| `C5_shutdown_deadline` | Hold A's original guarded probe beyond its 1000 ms budget; its caller times out and confirms metadata before the held read is released. Then kill A/delete cache. Hold the automatic resume's original Active HEAD PUT before forwarding. SIGINT and join its CLI while that server/S3 work remains outstanding. A fresh CLI recovers only the durable original plan and publishes Active. Release the late original PUT with unchanged body/If-Match; it must receive actual 412. | B Active, late original CAS rejected |

The core's accepted Claimed-to-abort operation directly publishes Aborted.
Cancelling is the distinct admission state when aborting an unaccepted
descriptor. The two C3 histories exercise those actual paths separately.

Every case seeds the same three original random SQL requests: two client ACKs
and one actual post-commit response loss reported as UNKNOWN. One S1 snapshot
captures the point after the first two writes. At the end, after all controllers
have stopped, principal 11 performs read-only lookups of all three original
requests, a native query checking the final original nondeterministic result,
snapshot inspection and current authority observation on M. No extra execute,
implicit SQL retry, replacement request ID, or manual activation is allowed.
`Database::session` authenticates READ and restores the immutable root without a
writer/active-owner requirement; `Session::query` rechecks current READ and aligns
the root with `writing=false`. This native cold read on M neither grants nor
certifies a writer. Inactive and blocked final states are intentional; verification must not turn
them into active states to manufacture a uniform outcome.
The final guarded status deliberately names A while contacting M. It proves
instance-route mismatch rejection before S3 I/O; it does not stand in for an
old native writer's fencing proof, which remains a separate lower-level gate.

## Original budgets and owned lifetimes

Production tick interval remains 5000 ms, failure count 3, minimum failure
spacing 1000 ms and failure span 5000 ms. Probe budget remains 1000 ms. Ordinary
tick deadline is 30000 ms; the explicitly configured recovery deadline is
60000 ms. Every tick retains production HTTP-call ceiling 8 and mutation ceiling
1. No fixture replaces clocks or reduces these thresholds.

Each case has one original 180-second whole-case alarm, except C1 and
C3_claimed_abort which have 240 seconds. An original stage wait is at most
75 seconds; a business subprocess is at most 45 seconds. Each signed S3 call
has a real 5000 ms client budget, except M in C4_resource_refusal which has an
original 15000 ms budget. That case starts the CLI only after the occupant's
actual HEAD GET arrives; this preserves a real intake lease through the first
429 response without racing a 5000 ms service timeout against a 5000 ms tick.
Service admission uses 30000 ms ordinary and
60000 ms recovery budgets. Existing observer bounds remain: HTTP at most 16
handlers, 10000 requests, 128 gates, bounded request/header/response bytes and
owned handler joins; S3 gates retain their fixed release bound. Cleanup keeps
the existing fixed per-process and per-proxy joins and records all failures.
No assertion enlarges a failed deadline or silently retries a failed case.

The C5 late request is intentionally still held by the observing proxy after
its original caller/server deadline. Its later delivery to S3 is the original
signed request and original conditional body, not a newly admitted controller
operation. Process exit does not assert that an already forwarded server effect
was cancelled. CLI output alone never proves native publication or current
authority.

Two CLIs sharing a principal can share one HTTP route. Their original process
overlap, configurations, byte streams and combined owner request ledger are
recorded. The fixture does not invent a per-process/per-tick attribution for
indistinguishable wire requests. Exact per-tick resource enforcement remains
covered separately by complete units and process/HTTP loopbacks; this matrix
checks real policy decisions and durable effects.

## Evidence and independent acceptance

The suite root has `cases.json`, which states all twelve expected cases, selected
cases and whether the run is complete, plus a summary. A partial `--case` run is
diagnostic evidence only. No subset can acquire a complete-matrix verdict.

Each case directory contains:

- `scenario.json` with the exact immutable case inputs, and `inputs.json` binding
  those bytes, PLAN hash, clean source commit/manifest/archive, actual executable
  hashes, Node version and all fixed budgets, the absolute execution source root
  and complete first-party JavaScript input map;
- `source.json`, `source.tar` and `service-build/`, including equality of all 277
  release inputs to the current source rather than inheriting an earlier verdict;
- `events.jsonl` and content-addressed `raw/` bytes from original process, HTTP
  and SigV4/S3 observers; HTTP keys are `(role, serial)` and S3 keys likewise;
- public `controller-*.json` and daemon configurations, token hashes only;
- `intents.json`, `business.jsonl`, `http-client-ledger.jsonl`, `transport.jsonl`
  and original snapshot input/result, preserving original ACK/result bytes;
- `summary.json`, and `failure.txt` whenever the observation failed.

Events retain the existing observer schema. `scenario_phase` marks orchestration
only. `controller_configuration` binds a real child's public config;
`controller_report_observed`, `controller_report_cut` and `controller_reports`
record genuine output but are not authority. Bounded status cuts emit
`http_proxy_cut_started/ended`, then ordinary per-request fault and suppressed
delivery events. A prearmed pair of holds is queued atomically, avoiding an
uncontrolled gap between racing requests. Losing a held preparation's response
emits `http_proxy_response_loss_requested`, followed by the real backend response
and a suppressed delivery; no response bytes are changed.

Before every Node child is spawned, `node_source_bound` records its exact
absolute entry, entry hash and the complete SDK, codec and business-observer
input map checked against the frozen source. Controller and business entries
are both covered. The runner rejects `NODE_OPTIONS`/`NODE_PATH` preload or loader
overrides; a matching filename suffix alone is insufficient. The oracle binds
this event, original argv, input map and source archive, and requires the binding
before the real child start. Existing whole-source after-capture remains required.

The independent oracle must first validate complete raw framing, source/binary
binding, process/proxy cleanup, original request/response correlation and actual
signed storage results. It then verifies each required case, the exact immutable
descriptor and accepted marker, current authorization and final HEAD, and all
three original business results plus retained S1 point. Any successful resume
must be proven by its original successful HTTP response, original prepare/claim
reference and current marker/status, not by an active CLI report. Every observed
HEAD CAS must use its original exact conditional ETag; C5 requires its late 412.

The negative-control denominator is fixed at 31. The groups are:

| Original observation changed | Count |
| --- | --- |
| S3 signature, HTTP operation/body agreement, controller SQL prohibition | 3 |
| Conditional HEAD header, late candidate's original GET/ETag, unchanged late body | 3 |
| Descriptor hash, claim target guard, real Active HTTP, accepted reference, accepted nonce | 5 |
| Controller per-tick mutation ceiling | 1 |
| Original ACK presence/bytes, UNKNOWN, recovered result, retained point reference, native random query result | 6 |
| Owned wait4 source and actual cache removal | 2 |
| Original HTTP 429/413 status and S3 Unknown classification | 3 |
| Late original aborted resume, original SDK request hash | 2 |
| Fresh foreign-policy/creator reports and original first-candidate cut target | 3 |
| Absolute Node entry, frozen JavaScript inputs, absence of unbound runtime options | 3 |

Every control requires its named rejection guard; an unrelated earlier error is
a failed control. The complete original suite is independently audited first,
and the original evidence inventory must remain unchanged after controls. Only
separate negative copies and targeted byte-reference overlays may be saved.

Targeted negative controls must corrupt one referenced observation at a time,
preserve source evidence, and be rejected for the intended invariant. Shared
content-addressed bodies must not be rewritten globally. Keep all failed actual,
oracle and control attempts; a new accepted fixture revision requires fresh
actual -> oracle -> controls. This local contract makes no AWS, production SLO,
unbounded-fleet, global hard-RSS, hard-disk or sustained-throughput claim.
