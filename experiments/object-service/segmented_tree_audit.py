"""Independent HEAD4/tree decoder for the real segmented-index experiment.

This module imports no controller and no Rust codec. Its graph walk checks every
retained branch and actual result; parent summaries never replace a child read.
"""
from __future__ import annotations

import hashlib
import re
import struct

from audit_wire import equal, parse, require, result

SCOPE = {"deployment": 1, "tenant": 7, "database": 991, "incarnation": 1, "generation": 1}
PREFIX = "/scap-test/scap-object/v1/1/7/991/inc/1/gen/1/objects/"
HEAD = "/scap-test/scap-object/v1/1/7/991/head"
MAX_RESULT = 64 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def uint(value, maximum=2**64 - 1, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, "integer bound/type")
    return value


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "SHA-256 shape")
    return value


def transition(value):
    require(set(value) == {"revision", "nonce"}, "transition fields")
    for item in value.values(): uint(item, minimum=1)


def request(value, epoch):
    require(set(value) == {"epoch", "id", "principal", "fingerprint"}, "complete request fields")
    for name in ("epoch", "id", "principal"): uint(value[name], minimum=1)
    require(value["epoch"] == epoch, "request escaped node epoch")
    digest(value["fingerprint"])


def envelope(raw, key):
    require(key.startswith(PREFIX) and key == PREFIX + digest(key[len(PREFIX):]), "object key scope")
    require(len(raw) >= 20 and raw[:8] == b"SCAPOBJ2" and sha(raw) == key[len(PREFIX):], "immutable bytes/key mismatch")
    metadata_bytes, raw_bytes = struct.unpack_from("<IQ", raw, 8)
    require(metadata_bytes <= 65536 - 20 and len(raw) == 20 + metadata_bytes + raw_bytes, "immutable frame bound/length")
    metadata = parse(raw[20:20 + metadata_bytes])
    require(set(metadata) == {"format", "scope", "payload"} and type(metadata["format"]) is int and metadata["format"] == 2,
            "immutable metadata format")
    equal(metadata["scope"], SCOPE, "immutable full scope")
    payload = metadata["payload"]
    require(set(payload) == {"kind", "value"}, "typed payload fields")
    return payload["kind"], payload["value"], raw[20 + metadata_bytes:]


def head(raw):
    value = parse(raw)
    require(set(value) == {"format", "scope", "revision", "transition", "sequence", "owner_epoch", "owner_instance",
            "active", "auth_epoch", "policy", "lifecycle", "creation", "deletion", "data_root", "quota", "retention",
            "request_epoch", "windows"}, "HEAD4 fields")
    require(type(value["format"]) is int and value["format"] == 4, "strict HEAD4 required")
    equal(value["scope"], SCOPE, "HEAD complete scope")
    for name in ("revision", "owner_epoch", "owner_instance", "auth_epoch", "request_epoch"):
        uint(value[name], minimum=1)
    uint(value["sequence"]); transition(value["transition"])
    require(value["transition"]["revision"] == value["revision"] and type(value["active"]) is bool, "HEAD revision/active")
    require(value["lifecycle"] == "ready" and value["creation"] is None and value["deletion"] is None,
            "fixture lifecycle changed")
    digest(value["data_root"])
    policy = value["policy"]
    require(isinstance(policy, list) and 0 < len(policy) <= 4096 and len({p["principal"] for p in policy}) == len(policy), "HEAD policy extent")
    for permission in policy:
        require(set(permission) == {"principal", "read", "write", "admin"}, "policy fields")
        uint(permission["principal"], minimum=1)
        require(all(type(permission[n]) is bool for n in ("read", "write", "admin")), "policy booleans")
    require(any(p["admin"] for p in policy), "HEAD has no administrator")
    quota, retention = value["quota"], value["retention"]
    require(set(quota) == {"max_bytes"}, "quota fields")
    if quota["max_bytes"] is not None:
        uint(quota["max_bytes"], (2**32 - 2) * 4096, 4096)
        require(quota["max_bytes"] % 4096 == 0, "quota page alignment")
    require(set(retention) == {"max_entries", "max_result_bytes"}, "retention fields")
    uint(retention["max_entries"], 65536, 1); uint(retention["max_result_bytes"], minimum=MAX_RESULT)
    windows = value["windows"]
    require(isinstance(windows, list) and len(windows) == min(value["request_epoch"], 3), "retained window inventory")
    for offset, window in enumerate(windows):
        require(set(window) == {"epoch", "root", "count", "result_bytes"}, "window fields")
        require(uint(window["epoch"], minimum=1) == value["request_epoch"] - offset, "window epoch order")
        digest(window["root"]); uint(window["count"], retention["max_entries"])
        uint(window["result_bytes"], min(retention["max_result_bytes"], window["count"] * MAX_RESULT))
        if offset:
            require(window["count"] == retention["max_entries"] or window["result_bytes"] > retention["max_result_bytes"] - MAX_RESULT,
                    "historical window was not closed")
    return value


def summary(value):
    require(set(value) == {"first", "last", "count", "result_bytes"}, "child summary fields")
    uint(value["first"], minimum=1); uint(value["last"], minimum=value["first"])
    uint(value["count"], 65536, 1); uint(value["result_bytes"], value["count"] * MAX_RESULT)
    require(value["last"] - value["first"] >= value["count"] - 1, "summary range too small")


class Trees:
    def __init__(self, objects):
        self.objects = objects
        self.nodes = {}

    def load(self, key, kind):
        require(key in self.objects, "missing full graph dependency: " + key)
        actual, value, raw = envelope(self.objects[key], key)
        require(actual == kind, "wrong dependency type")
        return value, raw

    def node(self, digest_value, epoch):
        key = PREFIX + digest(digest_value)
        if key in self.nodes:
            proof = self.nodes[key]
            require(proof["epoch"] == epoch, "cached node epoch mismatch")
            return proof
        node, raw = self.load(key, "index")
        require(not raw and isinstance(node, dict) and uint(node.get("epoch"), minimum=1) == epoch, "index epoch/raw extent")
        if node.get("kind") == "leaf":
            require(set(node) == {"kind", "epoch", "entries"} and isinstance(node["entries"], list), "typed leaf fields")
            entries = tuple(node["entries"]); width = len(entries)
            require(width <= 128, "leaf overflow")
            previous = 0
            for entry in entries:
                require(set(entry) == {"request", "outcome", "result_bytes"}, "entry fields")
                request(entry["request"], epoch); uint(entry["result_bytes"], MAX_RESULT)
                require(entry["request"]["id"] > previous, "leaf IDs overlap/out of order")
                previous = entry["request"]["id"]
                outcome = entry["outcome"]
                if outcome.get("state") == "committed":
                    require(set(outcome) == {"state", "result"}, "committed entry fields")
                    digest(outcome["result"])
                else:
                    require(set(outcome) == {"state", "transition"} and outcome["state"] == "cancelled", "cancelled entry fields")
                    transition(outcome["transition"])
                    require(entry["result_bytes"] == 0, "cancelled entry declared result bytes")
            aggregate = {"first": entries[0]["request"]["id"] if entries else 0,
                         "last": entries[-1]["request"]["id"] if entries else 0,
                         "count": width, "result_bytes": sum(entry["result_bytes"] for entry in entries)}
            level, dependencies = 0, {key}
        else:
            require(set(node) == {"kind", "epoch", "level", "children"} and node["kind"] == "branch", "typed branch fields")
            level = uint(node["level"], 3, 1); children = node["children"]; width = len(children)
            require(isinstance(children, list) and 2 <= width <= 32, "branch width")
            previous, entries, dependencies = 0, (), {key}
            for child in children:
                require(set(child) == {"hash", "summary"}, "child reference fields")
                digest(child["hash"]); summary(child["summary"])
                claim = child["summary"]
                require(claim["first"] > previous and 64 * 16**(level - 1) <= claim["count"] <= 128 * 32**(level - 1),
                        "child range overlap/count at level")
                previous = claim["last"]
                # Validate decreasing levels before recursing. A malformed cycle
                # cannot recurse indefinitely, even if content hashes are forged.
                child_value, child_raw = self.load(PREFIX + child["hash"], "index")
                actual_level = 0 if child_value.get("kind") == "leaf" else child_value.get("level")
                require(not child_raw and actual_level == level - 1, "child level does not decrease")
                child_proof = self.node(child["hash"], epoch)
                require(child_proof["width"] >= (64 if actual_level == 0 else 16), "underfull non-root node")
                equal(child_proof["summary"], claim, "child aggregate differs from actual complete subtree")
                require(not dependencies.intersection(child_proof["dependencies"]), "repeated subtree dependency")
                dependencies.update(child_proof["dependencies"]); entries += child_proof["entries"]
            aggregate = {"first": children[0]["summary"]["first"], "last": children[-1]["summary"]["last"],
                         "count": sum(c["summary"]["count"] for c in children),
                         "result_bytes": sum(c["summary"]["result_bytes"] for c in children)}
            require(aggregate["count"] <= 65536, "index window limit exceeded")
        proof = {"epoch": epoch, "level": level, "width": width, "summary": aggregate,
                 "entries": entries, "dependencies": dependencies}
        self.nodes[key] = proof
        return proof

    def index(self, window, authority):
        proof = self.node(window["root"], window["epoch"])
        require(proof["summary"]["count"] == window["count"] and proof["summary"]["result_bytes"] == window["result_bytes"],
                "HEAD window aggregate differs from complete tree")
        dependencies = set(proof["dependencies"])
        for entry in proof["entries"]:
            outcome = entry["outcome"]
            if outcome["state"] == "committed":
                key = PREFIX + outcome["result"]
                stored, raw = self.load(key, "result"); dependencies.add(key)
                require(set(stored) == {"request", "sequence", "transition", "data_root", "bytes"} and stored["bytes"] == [], "stored result fields")
                equal(stored["request"], entry["request"], "result complete identity differs")
                require(len(raw) == entry["result_bytes"] <= MAX_RESULT, "retained result actual byte count differs")
                uint(stored["sequence"], authority["sequence"], 1); transition(stored["transition"])
                require(stored["transition"]["revision"] <= authority["revision"] and
                        stored["transition"]["nonce"] == stored["request"]["id"], "result transition not in HEAD authority")
                digest(stored["data_root"]); result(raw)
            else:
                require(outcome["transition"]["revision"] <= authority["revision"], "future cancellation")
        return {**proof, "dependencies": dependencies}

    def data(self, root):
        key = PREFIX + digest(root); manifest, raw = self.load(key, "manifest")
        require(not raw and set(manifest) == {"page_count", "root"}, "data manifest fields")
        pages = uint(manifest["page_count"], 8192); dependencies = {key}
        if pages == 0:
            require(manifest["root"] is None, "empty manifest has root")
            return dependencies, b""
        node_key = PREFIX + digest(manifest["root"]); dependencies.add(node_key)
        node, raw = self.load(node_key, "node")
        require(not raw and set(node) == {"level", "first_chunk", "children"} and node["level"] == 0 and node["first_chunk"] == 0,
                "fixture page node shape")
        require(len(node["children"]) == (pages + 31)//32, "page node complete extent")
        pieces = []
        for index, child in enumerate(node["children"]):
            child_key = PREFIX + digest(child); dependencies.add(child_key)
            chunk, raw = self.load(child_key, "chunk")
            equal(chunk, {"first_page": index*32 + 1, "bytes": []}, "chunk position/metadata")
            require(len(raw) == min(32, pages - index*32) * 4096, "chunk byte extent")
            pieces.append(raw)
        image = b"".join(pieces)
        require(image[:16] == b"SQLite format 3\0" and image[16:18] == b"\x10\0", "SQLite page header")
        return dependencies, image
