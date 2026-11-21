"""Independent small-profile closure and publication proof, no product imports."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "object-service"))
from audit_wire import equal, head5_profile, require, result, sha256_text  # noqa: E402
from owner_oracle import object_frame  # noqa: E402
from spec import PREFIX, SCOPE  # noqa: E402

NATIVE_SCOPE = {key: int(value) for key, value in SCOPE.items()}


def load(objects, digest, kind):
    key = PREFIX + sha256_text(digest)
    require(key in objects, "missing complete immutable dependency")
    payload, raw = object_frame(objects[key], key)
    require(set(payload) == {"kind", "value"} and payload["kind"] == kind, "wrong dependency type")
    return payload["value"], raw, key


def data(objects, root):
    manifest, raw, key = load(objects, root, "manifest")
    dependencies = {key}
    require(not raw and set(manifest) == {"page_count", "root"}
            and type(manifest["page_count"]) is int and 0 <= manifest["page_count"] <= 32,
            "fixed data extent changed")
    pages = manifest["page_count"]
    if pages == 0:
        require(manifest["root"] is None, "empty manifest has a page root")
        return dependencies, b""
    node, raw, key = load(objects, manifest["root"], "node")
    dependencies.add(key)
    require(not raw and set(node) == {"level", "first_chunk", "children"}
            and node["level"] == node["first_chunk"] == 0 and len(node["children"]) == 1,
            "fixed data node extent changed")
    chunk, raw, key = load(objects, node["children"][0], "chunk")
    dependencies.add(key)
    equal(chunk, {"first_page": 1, "bytes": []}, "chunk offset changed")
    require(len(raw) == pages * 4096 and raw[:18] == b"SQLite format 3\0\x10\0", "SQLite image extent changed")
    return dependencies, raw


def closure(objects, head):
    head5_profile(head)
    equal(head["scope"], NATIVE_SCOPE, "HEAD full scope changed")
    require(head["request_epoch"] == 1 and len(head["windows"]) == 1, "fixture request epoch changed")
    dependencies, image = data(objects, head["data_root"])
    window = head["windows"][0]
    node, raw, key = load(objects, window["root"], "index")
    dependencies.add(key)
    require(not raw and set(node) == {"kind", "epoch", "entries"}
            and node["kind"] == "leaf" and node["epoch"] == 1, "fixed index leaf changed")
    require(len(node["entries"]) == window["count"] <= 128, "complete retained count changed")
    entries, stored, total, previous = {}, {}, 0, 0
    for entry in node["entries"]:
        require(set(entry) == {"request", "outcome", "result_bytes"}, "index entry fields changed")
        request = entry["request"]
        require(set(request) == {"epoch", "id", "principal", "fingerprint"}
                and request["epoch"] == 1 and request["principal"] == 11
                and type(request["id"]) is int and previous < request["id"] < 2**64,
                "request identity or ordering changed")
        sha256_text(request["fingerprint"])
        previous = request["id"]
        outcome = entry["outcome"]
        require(type(entry["result_bytes"]) is int and 0 <= entry["result_bytes"] <= 64 * 1024 * 1024,
                "entry result byte bound")
        if outcome["state"] == "committed":
            require(set(outcome) == {"state", "result"}, "committed index fields changed")
            value, raw, key = load(objects, outcome["result"], "result")
            dependencies.add(key)
            require(set(value) == {"request", "sequence", "transition", "data_root", "bytes"}
                    and value["bytes"] == [] and len(raw) == entry["result_bytes"], "original result extent changed")
            equal(value["request"], request, "stored full identity changed")
            require(type(value["sequence"]) is int and 0 < value["sequence"] <= head["sequence"],
                    "stored result sequence outside HEAD")
            transition = value["transition"]
            require(set(transition) == {"revision", "nonce"} and type(transition["revision"]) is int
                    and 0 < transition["revision"] <= head["revision"] and transition["nonce"] == request["id"],
                    "stored original transition changed")
            sha256_text(value["data_root"])
            result(raw)
            stored[request["id"]] = {"metadata": value, "raw": raw, "hash": outcome["result"]}
        else:
            require(set(outcome) == {"state", "transition"} and outcome["state"] == "cancelled"
                    and entry["result_bytes"] == 0, "invalid cancelled barrier")
            transition = outcome["transition"]
            require(set(transition) == {"revision", "nonce"} and type(transition["revision"]) is int
                    and 0 < transition["revision"] <= head["revision"] and transition["nonce"] == request["id"],
                    "cancel transition changed")
        entries[request["id"]] = entry
        total += entry["result_bytes"]
    require(total == window["result_bytes"], "complete retained byte count changed")
    return {"dependencies": dependencies, "image": image, "entries": entries, "stored": stored}


def publication(previous, candidate, before, after):
    """A +k exception requires exactly k new original committed records.

    Every ordinary control remains +1. Existing entries and all protected
    authority fields must survive unchanged; a final-state count is not proof.
    """
    old, new = before["entries"], after["entries"]
    require(set(old) <= set(new), "group removed retained identities")
    for identifier in old:
        equal(old[identifier], new[identifier], "group rewrote a retained identity")
    added = [identifier for identifier in new if identifier not in old]
    count = candidate["sequence"] - previous["sequence"]
    if count:
        require(1 <= count <= 4 and len(added) == count, "logical group width differs from fresh identities")
        require(all(new[identifier]["outcome"]["state"] == "committed" for identifier in added),
                "group replaced a cancellation barrier")
        members = sorted((after["stored"][identifier] for identifier in added), key=lambda row: row["metadata"]["sequence"])
        for offset, member in enumerate(members, 1):
            value = member["metadata"]
            require(value["sequence"] == previous["sequence"] + offset
                    and value["transition"]["revision"] == previous["revision"] + offset,
                    "member sequence/revision is not its independent transaction")
        last = members[-1]["metadata"]
        allowed = dict(previous, revision=previous["revision"] + count, sequence=previous["sequence"] + count,
            head_serial=previous["head_serial"] + count, transition=last["transition"],
            data_root=last["data_root"], windows=candidate["windows"])
        equal(candidate, allowed, "group changed protected authority or final member root")
        return members
    require(candidate["revision"] == previous["revision"] + 1
            and candidate["head_serial"] == previous["head_serial"] + 1, "ordinary control did not advance exactly once")
    if added:
        require(added == [72] and new[72]["outcome"]["state"] == "cancelled", "unplanned control identity")
        allowed = dict(previous, revision=candidate["revision"], head_serial=candidate["head_serial"],
                       transition={"revision": candidate["revision"], "nonce": 72}, windows=candidate["windows"])
    else:
        require(candidate["transition"]["nonce"] in (2, 2001, 2002), "unplanned owner control")
        allowed = dict(previous, revision=candidate["revision"], head_serial=candidate["head_serial"],
            transition=candidate["transition"], active=candidate["active"],
            owner_epoch=candidate["owner_epoch"], owner_instance=candidate["owner_instance"])
        if candidate["transition"]["nonce"] == 2001:
            require(candidate["owner_epoch"] == previous["owner_epoch"] + 1 and not candidate["active"]
                    and candidate["owner_instance"] == 9202, "takeover owner binding changed")
        else:
            require(candidate["active"] and not previous["active"]
                    and candidate["owner_epoch"] == previous["owner_epoch"]
                    and candidate["owner_instance"] == previous["owner_instance"], "activation changed owner identity")
    equal(candidate, allowed, "ordinary control changed protected group data")
    return []


def receipt_matches(receipt, raw, stored):
    value = stored["metadata"]
    equal(receipt["scope"], SCOPE, "receipt changed logical scope")
    equal(receipt["request"], {key: str(item) if key != "fingerprint" else item
                              for key, item in value["request"].items()}, "receipt changed original full identity")
    equal(receipt["transition"], {key: str(item) for key, item in value["transition"].items()},
          "receipt changed independent transition")
    require(receipt["sequence"] == str(value["sequence"]) and receipt["data_root"] == value["data_root"]
            and receipt["result_hash"] == stored["hash"] and raw == stored["raw"], "receipt differs from original stored result")
