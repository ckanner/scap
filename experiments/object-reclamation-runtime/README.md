# Explicit HEAD6 compaction and reclamation: native runtime contract

This experiment exercises the production `scapd`, native SQLite seed worker,
Node SDK, and a pinned authenticated SeaweedFS S3 backend. The runner assembles
those components and introduces explicit transport cuts. It does not implement
the product's copy, fencing, retirement, or deletion algorithm.

`PLAN.md` is the pre-execution contract. A completed runner reports
`OBSERVED_NOT_AUDITED`; only the separate raw oracle and its whole-history
negative controls establish a passing observation. This source tree does not
claim an actual run merely because its observer unit tests pass.

## Fixed workload

| Scope | Original data and retained outcomes | Maintenance and faults |
| --- | --- | --- |
| database 4101 | 260 successful original SQL requests, two genuinely closed windows of 129 entries, two current successful entries, one current cancellation | Full retained closure copy, concurrent valid policy update, promotion, durable GC checkpoint across a new worker, old source GET expiration, original delayed immutable PUT and a new sweep from the beginning |
| database 4102 | Two successful original requests; one separately saved, once-dispatched SQL attempt whose response remains unknown | Original old HEAD candidate receives a real backend 412, pending DELETE survives process loss, another copy and promotion completes before the old DELETE is released |
| database 4103 | Two successful original requests | Copy followed by Abort, checkpoint restart, backend-accepted DELETE with lost response, true multipart same-byte/different-ETag recreation, original ETag receives real 412, next batch captures the new ETag, NoSuchBucket cannot clear pending work |

The native seed sets persisted retention to 129 entries per window and 256 MiB
of retained result bytes, with a 64 MiB database quota. It closes windows through
the formal core API. It never writes a synthetic HEAD to manufacture these
states. Each original result contains a random value and a random 64-byte BLOB;
the external ACK's complete bytes remain the recovery expectation. Every one
of 264 acknowledged requests is looked up through its original saved SDK
identity after all compute processes and caches have been removed. The final
three business queries also compare their counter and payload to the original
inputs and final ACK.

The source GET cut occurs after complete COPY and before PROMOTE. The first
GC page uses the observed hash's predecessor as its explicit frontier, so that
the delayed GET's object belongs to that page. The maintenance worker is
terminated and reaped after the checkpoint ACK, and a new worker resumes that
same batch. Only then is the original GET forwarded to the backend. Subsequent
full sweeps start again at `after=null`.

The configured S3 and service HTTP limits are 120 seconds; the normal SDK limit
is 90 seconds. Core lookup preserves its caller's deadline and does not apply
the 30-second default used by some other operations. This fixture additionally
requires the complete delayed reader observation to finish within 30 seconds;
that is an acceptance condition for this run, not a general product deadline
claim. Unknown calls keep their original references. No SQL is retried.

## Source and executable identity

The binary build commit and the fixture commit may differ. This is deliberate:
a production candidate can finish its expensive release builds before this
new independent experiment is committed. Both original release receipts must
name the same runtime commit, and **every** recorded production, SDK and native
assembler input must exactly match the corresponding committed file in the
clean fixture checkout. A changed production input fails before execution.

The evidence retains the full fixture source manifest and archive, the runtime
commit and original source roots, both original build archives and Cargo logs,
and SHA-256 identities of the exact service/native executables and libsql
archives. The independent oracle verifies these separately. It does not
relabel the later fixture commit as the executable's build commit.

## Run

Run from a clean committed checkout containing this directory. Use the original
unmodified release records and executables built by the existing official
builders. The shell below uses example absolute locations; set them to the
frozen candidate's actual artifacts. Each evidence directory must be new.

```bash
python3 -B -m unittest discover -s experiments/object-reclamation-runtime -p 'test_*.py'

python3 -B experiments/object-reclamation-runtime/run.py \
  --server /absolute/target/service/release/scapd \
  --build-record /absolute/evidence/service-build/build.json \
  --worker /absolute/target/native/release/scap-object-network \
  --seed-build-record /absolute/evidence/native-build/build.json \
  --weed /absolute/bin/weed \
  --node /absolute/bin/node \
  --evidence /absolute/evidence/reclamation-01

python3 -B experiments/object-reclamation-runtime/oracle.py \
  /absolute/evidence/reclamation-01 > /absolute/evidence/reclamation-01-oracle.json

python3 -B experiments/object-reclamation-runtime/controls.py \
  /absolute/evidence/reclamation-01 /absolute/evidence/reclamation-01-controls
```

The whole runner has a 1200-second deadline and each transport hold has its
own 180-second release bound. These limits are not refreshed after failures.
The seed uses the existing 8-second S3 assembler setting for each short seed
operation. The larger service maintenance deadline does not change seed inputs.

The evidence parent holds a private directory with temporary credentials,
service caches, and the isolated backend. Success removes it after every owned
process is reaped and every proxy thread has joined. Failure retains the
directory and original public evidence. Public evidence contains credential
digests and independently validated signature observations, not secrets or
bearer tokens. Reruns use a new directory; failures are not rewritten.

## Independent verdict

`audit_model.py` independently checks HEAD6 field invariants, irreversible
allocation, original plan basis, business versus technical serial changes,
checkpoint identity, and the full current data/index/result closure. It treats
historical `Result.data_root` as receipt metadata and verifies that COPY does
not turn those historical images into required roots.

`oracle.py` joins the original native/SDK inputs to raw HTTP and S3 records.
It verifies acknowledged native results against their actual immutable PUT,
exact readback and original HEAD CAS; all copy dependencies and target
readbacks must precede Seal. Each DELETE requires a fresh observation of the
same durable batch, permanent retirement, the original key and ETag, and the
configured distinct GC signing identity. Dispositions require delivered typed
outcomes in the corresponding resume operation. A lost response cannot be
counted as `applied`, and NoSuchBucket cannot be counted as an absent key.

The 23 negative controls operate on independent copies of a complete passing
raw history, including omission of an entire S3 exchange. Each must fail its named semantic boundary; an unrelated schema
failure is itself a failed control. They cover lost original ACK/result bytes,
closed-window omission, altered target bytes, missing readback, unsealed
publication, copying receipt-only historical roots, active generation DELETE,
wrong batch/ETag, fabricated successful disposition, bucket error clearing,
late PUT collection, reused frontier, old CAS acceptance, early old transport
release, SQL retry, lost unknown reference, fake wait4, cancellation loss, and
a repeated business effect. A whole unchanged copied history must still pass.
Target protection, exact state transitions, nonce binding and atomic raw
observation also have focused deterministic tests.

## Scope of the result

This is a bounded local compatible-backend acceptance contract. It is not AWS
Standard/IAM certification, a production throughput or latency SLO, an
automatic maintenance controller, PITR, retained snapshots, or a proof that a
namespace stays empty forever. An old authorized PUT can recreate an orphan
after one sweep; a later round must observe and collect it. The final active
generation of a logically Deleted database remains protected by HEAD6 and is
not claimed to be fully purged by this experiment.
