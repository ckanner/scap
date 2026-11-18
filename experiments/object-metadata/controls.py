#!/usr/bin/env python3
"""Nine metadata projection and six raw startup controls after a FULL audit.

These are explicitly NOT nine complete raw-ledger forgery tests. The original
file/sequence/handler/bytes references remain on every copied projection fact;
changes are recorded as hypothetical semantic mutations, never actual events.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile

import oracle


CASES = (
    ("immutable_get", "M_OBJECT_GET"),
    ("immutable_put", "M_OBJECT_PUT"),
    ("late_immutable_get", "M_TAIL_OBJECT_IO"),
    ("non_metadata_input", "M_NON_METADATA"),
    ("accepted_unknown_as_ack", "M_UNKNOWN_OUTCOME"),
    ("unknown_second_head_attempt", "M_PUBLICATION_ATTEMPT_COUNT"),
    ("conflict_rebound_etag", "M_ORIGINAL_ETAG"),
    ("repaired_handle_publication", "M_KNOWN_QUARANTINE"),
    ("denied_changed_principal", "M_PERMISSION"),
)

STARTUP_CASES = {
    'worker_missing_readback': 'worker-identity-request-denominator',
    'worker_wrong_body': 'worker-identity-exact-body',
    'worker_changed_etag': 'worker-identity-same-etag',
    'worker_replacement_create': 'worker-identity-absent-only',
    'worker_wrong_instance': 'worker-identity-exact-key',
    'worker_after_ready': 'worker-identity-before-ready',
}


def startup_mutated(original, events, name):
    """Raw startup exchange mutation; original lifecycle observations stay intact."""
    trace = deepcopy(original)
    path = '/scap-test/scap-worker/v1/instances/' + oracle.WORKERS['S']
    claims = [row for row in trace if row.get('path') == path]
    put = oracle.only([r for r in claims if r['event'] == 'object_response' and r['method'] == 'PUT'], 'original worker PUT')
    get = oracle.only([r for r in claims if r['event'] == 'object_request' and r['method'] == 'GET'], 'original worker GET')
    if name == 'worker_missing_readback':
        trace = [r for r in trace if r['handler_id'] != get['handler_id']]
    elif name == 'worker_wrong_body':
        wrong = b'SCAP-WORKER-INSTANCE-v1\0' + int(oracle.WORKERS['M']).to_bytes(8, 'big')
        for row in claims:
            if row['method'] == 'PUT':
                row.update(oracle.pack(wrong, 'request_body'))
                row['signing']['payload_sha256'] = oracle.sha(wrong)
            elif row['event'] in ('object_response', 'object_response_delivered'):
                row.update(oracle.pack(wrong, 'response_body'))
    elif name == 'worker_changed_etag':
        for row in claims:
            if row['method'] == 'GET' and row['event'] in ('object_response', 'object_response_delivered'):
                row['etag'] = '"different-original-readback"'
    elif name == 'worker_replacement_create':
        for row in claims:
            if row['method'] == 'PUT':
                row.update(if_match=put['etag'], if_none_match=None)
    elif name == 'worker_wrong_instance':
        for row in claims:
            row['path'] = '/scap-test/scap-worker/v1/instances/' + oracle.WORKERS['M']
    elif name == 'worker_after_ready':
        ready = oracle.only([r for r in events if r['event'] == 'service_ready' and r['worker'] == 'S'], 'original worker ready')
        handler = [r for r in trace if r['handler_id'] == get['handler_id']]
        delta = oracle.stamp(ready) + 1 - min(oracle.stamp(r) for r in handler)
        for row in handler:
            row['monotonic_ns'] = oracle.stamp(row) + delta
    else:
        raise ValueError(name)
    # Removing an entire exchange must not pass merely because of a serial or
    # handler gap. The exact missing marker readback remains the targeted rule.
    trace.sort(key=oracle.stamp)
    serials = {old: new for new, old in enumerate(sorted({r['request_serial'] for r in trace if 'request_serial' in r}), 1)}
    handlers, counts = {}, {}
    for row in trace:
        old, listener = row['handler_id'], row['listener_id']
        if old not in handlers:
            counts[listener] = counts.get(listener, 0) + 1
            handlers[old] = listener + ':' + str(counts[listener])
        row['handler_id'] = handlers[old]
        if 'request_serial' in row:
            row['request_serial'] = serials[row['request_serial']]
    for sequence, row in enumerate(trace, 1):
        row['sequence'] = sequence
    return trace


def call(projection, name):
    return oracle.only([row for row in projection["calls"] if row["command"] == name], "control command is absent")


def put(projection, name):
    return oracle.only([row for row in projection["stream"] if row["request"]["method"] == "PUT" and
                       row["request"]["path"] == oracle.head_path(name)], "control original PUT is absent")


def change_request(exchange, **fields):
    for key in ("request", "forwarded", "response", "terminal"):
        exchange[key].update(deepcopy(fields))


def change_response(exchange, **fields):
    for key in ("response", "terminal"):
        exchange[key].update(deepcopy(fields))


def move_exchange(exchange, start):
    for offset, key in enumerate(("request", "forwarded", "response", "terminal")):
        exchange[key]["monotonic_ns"] = start + offset


def immutable(projection, method, *, late=False):
    original = next(row for row in projection["immutable_samples"] if row["request"]["method"] == method)
    item = deepcopy(original)
    change_request(item, worker="M", listener_id="s3-M")
    # The original source reference is retained; no invented raw-ledger row is
    # represented as observed. Only this audited semantic input is altered.
    start = projection["last_http_response_ns"] + 1 if late else oracle.stamp(projection["stream"][0]["request"]) + 1
    oracle.require(start + 3 < projection["lifetime"]["service_wait4_ns"], "control cannot fit in original owned lifetime")
    move_exchange(item, start)
    if method == "PUT":
        # A different, valid noncanonical frame has a new immutable key. It is
        # a legal hypothetical conditional create, not a second 200 for an
        # already occupied key. The raw payload itself is left unchanged.
        raw = oracle.raw_bytes(item["request"], "request_body")
        metadata_length, raw_length = struct.unpack_from("<IQ", raw, 8)
        replacement = raw[:8] + struct.pack("<IQ", metadata_length + 1, raw_length) + b" " + raw[20:]
        path = item["request"]["path"].rsplit("/", 1)[0] + "/" + oracle.sha(replacement)
        oracle.frame(replacement, path)
        signing = deepcopy(item["request"]["signing"])
        signing["payload_sha256"] = oracle.sha(replacement)
        change_request(item, path=path, signing=signing, if_match=None, if_none_match="*", **oracle.pack(replacement, "request_body"))
        change_response(item, status=200, etag='"semantic-control-' + oracle.sha(replacement) + '"', **oracle.pack(b"", "response_body"))
    return item


def mutated(original, name):
    projection = deepcopy(original)
    refs = []
    if name in ("immutable_get", "immutable_put", "late_immutable_get"):
        item = immutable(projection, "PUT" if name == "immutable_put" else "GET", late=name == "late_immutable_get")
        projection["stream"].append(item)
        refs.append(item["source"])
    elif name == "non_metadata_input":
        target = call(projection, "m_success_status_before")
        target["request_body"] = {"version": 1, "scope": oracle.SCOPES["success"], "operation": "open"}
        refs.append(target["source"])
    elif name == "accepted_unknown_as_ack":
        target = call(projection, "m_put_unknown_policy")
        accepted = oracle.head(oracle.raw_bytes(put(projection, "put_unknown")["request"], "request_body"), "put_unknown")
        target.update(status=200, outcome={"ok": True, "value": oracle.status_from_head(accepted)})
        refs.append(target["source"])
    elif name == "unknown_second_head_attempt":
        item = deepcopy(put(projection, "put_unknown"))
        # Original accepted ETag was consumed. A second same-candidate attempt
        # can legally receive 412, but is still forbidden automatic retry.
        item["terminal"]["event"] = "object_response_delivered"
        item["terminal"].pop("fault_id", None)
        item["terminal"].pop("reason", None)
        rejected = put(projection, "stale_412")["response"]
        change_response(item, status=412, etag=rejected["etag"], **oracle.pack(oracle.raw_bytes(rejected, "response_body"), "response_body"))
        move_exchange(item, oracle.stamp(item["terminal"]) + 1)
        projection["stream"].append(item)
        refs.append(item["source"])
    elif name == "conflict_rebound_etag":
        item = put(projection, "stale_412")
        competitor = projection["competitor"]
        base = oracle.head(oracle.raw_bytes(competitor["request"], "request_body"), "stale_412")
        candidate = oracle.advance(base, 23001, owner_epoch=2, owner_instance=8202, active=False)
        raw = oracle.canonical(candidate)
        signing = deepcopy(item["request"]["signing"])
        signing["payload_sha256"] = oracle.sha(raw)
        change_request(item, if_match=competitor["response"]["etag"], signing=signing, **oracle.pack(raw, "request_body"))
        change_response(item, status=200, etag='"semantic-rebase-' + oracle.sha(raw) + '"', **oracle.pack(b"", "response_body"))
        target = call(projection, "m_stale_takeover")
        target.update(status=200, outcome={"ok": True, "value": oracle.status_from_head(candidate)})
        refs.extend([item["source"], competitor["source"], target["source"]])
    elif name == "repaired_handle_publication":
        target = call(projection, "m_quarantine_takeover")
        base = oracle.head(oracle.raw_bytes(projection["bases"]["known_quarantine"]), "known_quarantine")
        candidate = oracle.advance(base, 25001, owner_epoch=2, owner_instance=8202, active=False)
        target.update(status=200, outcome={"ok": True, "value": oracle.status_from_head(candidate)})
        refs.append(target["source"])
    elif name == "denied_changed_principal":
        target = call(projection, "m_permission_takeover")
        target["credential_sha256"] = projection["credentials"]["manager"]
        refs.append(target["source"])
    else:
        raise ValueError("unknown independent semantic control")
    oracle.require(projection != original, "control did not change audited semantics")
    return projection, refs


def directory_inventory(path):
    root = Path(path)
    inventory = []
    for file in sorted(root.rglob("*")):
        oracle.require(not file.is_symlink(), "positive copy cannot silently dereference original symlinks")
        if file.is_file():
            inventory.append({"path": file.relative_to(root).as_posix(), "bytes": file.stat().st_size,
                              "sha256": oracle.BUILD.file_digest(file)})
        else:
            oracle.require(file.is_dir(), "nonregular original evidence")
    return inventory


def run(directory):
    directory = Path(directory)
    baseline, projection = oracle.audit(directory, include_projection=True)
    # The identity-positive copy runs the entire raw/source/build/process audit;
    # it cannot be made green by a projection-only shortcut or run path change.
    original_inventory = directory_inventory(directory)
    with tempfile.TemporaryDirectory(prefix="scap-metadata-positive-", dir="/tmp") as private:
        copied = Path(private) / "evidence"
        shutil.copytree(directory, copied)
        oracle.equal(directory_inventory(copied), original_inventory, "whole-directory positive copy changed bytes")
        positive = oracle.audit(copied)
        oracle.equal(positive, baseline, "byte-identical copied evidence produced another audit verdict")
    outcomes = []
    for name, expected in CASES:
        changed, references = mutated(projection, name)
        failure = None
        try:
            oracle.metadata_semantics(changed)
        except oracle.SemanticFailure as error:
            failure = {"type": type(error).__name__, "rule": error.rule, "message": str(error)}
        except Exception as error:
            # Preserve unrelated rejection; never label schema/KeyError/hash
            # failure as successful testing of the intended semantic rule.
            failure = {"type": type(error).__name__, "rule": None, "message": str(error)}
        outcomes.append({"name": name, "expected_rule": expected, "observed_failure": failure,
                         "status": "passed" if failure is not None and failure["rule"] == expected else "failed",
                         "original_references": references, "before_sha256": oracle.sha(oracle.canonical(projection)),
                         "after_sha256": oracle.sha(oracle.canonical(changed)), "changed_projection": changed})
    startup_outcomes = []
    trace, events = oracle.rows(directory, 's3.jsonl'), oracle.rows(directory, 'events.jsonl')
    with tempfile.TemporaryDirectory(prefix='scap-metadata-startup-', dir=directory.parent) as private:
        for name, expected in STARTUP_CASES.items():
            copied = Path(private) / name
            # Only s3.jsonl is replaced; immutable original raw files stay linked.
            shutil.copytree(directory, copied, copy_function=os.link)
            changed = startup_mutated(trace, events, name)
            path = copied / 's3.jsonl'
            path.unlink()
            path.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in changed))
            observed = None
            try:
                oracle.audit(copied)
            except Exception as error:
                observed = {'type': type(error).__name__, 'message': str(error)}
            startup_outcomes.append({'name': name, 'expected_rule': expected, 'observed_failure': observed,
                                     'status': 'passed' if observed == {'type': 'ValueError', 'message': expected} else 'failed',
                                     'before_sha256': oracle.sha(oracle.canonical(trace)),
                                     'after_sha256': oracle.sha(oracle.canonical(changed))})
            shutil.rmtree(copied)
    oracle.equal(directory_inventory(directory), original_inventory, "controls changed original evidence")
    return {"schema": 1, "status": "passed" if all(item["status"] == "passed" for item in [*outcomes, *startup_outcomes]) else "failed",
            "profile": "independent-metadata-semantic-projection-controls-v1",
            "original_full_audit": {"status": baseline["status"], "evidence_sha256": baseline["evidence_sha256"],
                                    "source": baseline["source"], "projection_sha256": baseline["projection_sha256"]},
            "positive_copy": {"status": "passed", "scope": "entire copied raw evidence audited again",
                              "files": len(original_inventory), "inventory_sha256": oracle.sha(oracle.canonical(original_inventory)),
                              "evidence_sha256": positive["evidence_sha256"]},
            "negative_controls": outcomes, "negative_count": 9,
            "startup_negative_controls": startup_outcomes, "startup_negative_count": len(startup_outcomes),
            "boundary": "Nine metadata semantic projection mutations plus six complete raw-ledger startup audits; all originals remain unchanged"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new JSON file, not a directory")
    args = parser.parse_args()
    try:
        value = run(args.evidence)
    except Exception as error:
        value = {"schema": 1, "status": "failed", "error_type": type(error).__name__, "error": str(error)}
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")
    print(json.dumps({"status": value["status"], "output": str(args.output), "negative_count": value.get("negative_count", 0)}, sort_keys=True))
    return 0 if value["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
