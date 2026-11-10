"""Deliberately unsafe protocol variants and observer mutations.

Each returned history keeps the concrete offending request or observation.
No expected rule is read by the independent oracle.
"""
from copy import deepcopy

from model import Model, Rejected, head_key, payload_key


def seal(model):
    model.run(model.prepare_terminal("seal"))


def batch(model):
    model.run(model.prepare_checkpoint("batch"))


def collect(model):
    batch(model)
    model.run(model.prepare_delete("delete"))
    model.run(model.prepare_settle("settle", delete_call="delete"))
    model.run(model.prepare_clear("clear"))


def record(name, rule, model, kind="protocol_variant"):
    return {"name": name, "expected_rule": rule, "kind": kind, "history": model.history()}


def examples():
    m = Model(fault="deleted_is_retired")
    collect(m)
    yield record("bare-deleted-authorizes-last-a", "explicit_retirement_before_gc", m)

    m = Model("abort", fault="change_business_barrier")
    m.run(m.prove_abort())
    seal(m)
    try:
        m.recover_intent()
    except Rejected:
        pass
    yield record("seal-rewrites-own-deleted-transition", "business_barrier", m)

    m = Model(fault="refresh_delete_etag")
    seal(m)
    batch(m)
    m.run(m.prepare_delete("lost"), lost=True)
    m.run("old-put")
    m.run(m.prepare_delete("refreshed"))
    yield record("inspect-refreshes-checkpoint-condition", "original_delete_etag", m)

    m = Model(fault="unknown_is_applied")
    seal(m)
    batch(m)
    m.invoke(m.prepare_delete("lost"))
    m.timeout("lost")
    m.run(m.prepare_settle("settle", delete_call="lost"))
    m.run(m.prepare_clear("clear"))
    yield record("unknown-delete-recorded-applied", "unknown_not_disposition", m)

    m = Model()
    seal(m)
    collect(m)
    m.run(m.destroy_metadata(head_key()))
    m.run("old-create")
    yield record("delete-permanent-head-reopens-absent-create", "permanent_metadata", m)

    m = Model("delete", fault="ignore_missing_intent")
    m.corrupt_authority("control:51")
    seal(m)
    yield record("seal-accepts-missing-actual-control", "catalogue_authority", m)

    m = Model()
    seal(m)
    observed = m.get(head_key())
    revived = deepcopy(observed["body"])
    revived.update(format=6, terminal=None, lifecycle="ready", serial=revived["serial"] + 1)
    m.run(m._prepare("revive", "old_head", "PUT", head_key(), observed["etag"], revived, [observed["id"]]))
    yield record("fresh-cas-unseals-terminal", "terminal_monotonicity", m)

    m = Model()
    seal(m)
    observed = m.get(head_key())
    allocated = deepcopy(observed["body"])
    allocated.update(allocated=allocated["allocated"] + 1, serial=allocated["serial"] + 1)
    m.run(m._prepare("allocate", "old_head", "PUT", head_key(), observed["etag"], allocated, [observed["id"]]))
    yield record("terminal-allocates-new-generation", "terminal_monotonicity", m)

    m = Model()
    m.prepare_terminal("unsent")
    m.crash()
    m.calls["unsent"].process = m.process
    m.run("unsent")
    yield record("restart-reuses-old-unsent-candidate", "fresh_process_invocation", m)

    m = Model()
    observed, reads = m.authority()
    body = m.technical(observed["body"])
    body.update(format=7, active=False, terminal={"serial": body["serial"]})
    m.run(m._prepare("seal", "terminal", "PUT", head_key(), observed["etag"], body, reads, principal=8))
    yield record("seal-without-current-admin", "current_admin", m)

    m = Model("foreign")
    observed = m.get(head_key())
    body = m.technical(observed["body"])
    body.update(format=7, lifecycle="deleted", active=False, terminal={"serial": body["serial"]})
    m.run(m._prepare("foreign-seal", "terminal", "PUT", head_key(), observed["etag"], body, [observed["id"]]))
    yield record("foreign-proof-treated-as-owned-authority", "scope_binding", m)

    m = Model()
    seal(m)
    bad = deepcopy(m.store[payload_key()]["body"])
    bad["semantic"] = "bad"
    m.corrupt_authority(payload_key(), bad)
    m.run("old-read")
    m.reader_reply()
    m.semantic_latch = False
    batch(m)
    yield record("terminal-clears-semantic-latch", "lineage_publication_gate", m)

    m = Model()
    seal(m)
    collect(m)
    m.run("old-read")
    m.reader_reply()
    m.tick(10)
    m.reader["deadline"] = 11
    m.diagnose()
    yield record("diagnostic-extends-original-deadline", "original_deadline", m)

    m = Model(initial_serial=10, fault="ignore_terminal_era")
    seal(m)
    collect(m)
    m.run("old-read")
    m.reader_reply()
    impossible = deepcopy(m.store[head_key()]["body"])
    impossible["terminal"]["serial"] = 3
    m.corrupt_authority(head_key(), impossible)
    m.diagnose()
    yield record("terminal-seal-predates-original-live-context", "strict_expiry_proof", m)

    m = Model("delete")
    seal(m)
    case = record("candidate-omits-stable-name-observation", "stable_catalogue_view", m, "observer_mutation")
    prepared = next(event for event in case["history"]["events"] if event["event"] == "prepare" and event["kind"] == "terminal")
    by_id = {event["sequence"]: event for event in case["history"]["events"]}
    first_name = next(token for token in prepared["observations"] if by_id[token]["key"] == "name:demo")
    prepared["observations"].remove(first_name)
    yield case

    m = Model()
    seal(m)
    bad = deepcopy(m.store[payload_key()]["body"])
    bad["semantic"] = "bad"
    m.corrupt_authority(payload_key(), bad)
    m.run("old-read")
    m.reader_reply()
    case = record("semantic-error-labelled-snapshot-expired", "failure_provenance", m, "observer_mutation")
    next(event for event in case["history"]["events"] if event["event"] == "reader_reply")["state"]["outcome"] = "snapshot_expired"
    yield case

    m = Model()
    seal(m)
    collect(m)
    m.run("old-read")
    m.reader_reply()
    m.diagnose("unknown")
    case = record("unknown-head-labelled-retirement-proof", "strict_expiry_proof", m, "observer_mutation")
    next(event for event in case["history"]["events"] if event["event"] == "diagnostic")["state"]["outcome"] = "snapshot_expired"
    yield case

    m = Model()
    seal(m)
    m.late_receipt(native_failure=True)
    case = record("known-commit-converted-to-expired", "known_receipt_preserved", m, "observer_mutation")
    next(event for event in case["history"]["events"] if event["event"] == "receipt_reply")["outcome"] = "snapshot_expired"
    yield case

    m = Model()
    seal(m)
    batch(m)
    try:
        m.prepare_delete("delete", inspect_failure="unknown")
    except Rejected:
        pass
    case = record("unknown-inspect-forged-as-key-absence", "exact_get", m, "observer_mutation")
    next(event for event in case["history"]["events"] if event["event"] == "get" and event["result"] == "unknown")["result"] = "missing"
    yield case

    # The stored metadata is actually malformed. This observer mutation then
    # falsely treats that GET as a retirement proof; it is not a legal API path.
    m = Model()
    seal(m)
    collect(m)
    m.run("old-read")
    m.reader_reply()
    malformed = deepcopy(m.store[head_key()]["body"])
    malformed["revision"] = malformed["terminal"]["serial"]
    m.corrupt_authority(head_key(), malformed)
    m.diagnose()
    case = record("terminal-seal-not-after-business-revision", "strict_expiry_proof", m, "observer_mutation")
    next(event for event in case["history"]["events"] if event["event"] == "diagnostic")["state"]["outcome"] = "snapshot_expired"
    yield case


if __name__ == "__main__":
    import json
    print(json.dumps([{k: v for k, v in example.items() if k != "history"} for example in examples()], indent=2))
