"""Independent complete typed closure decoder; never imports a controller.

HEAD4 is deliberate. A storage-format upgrade must change this strict profile
and be revalidated; this reader never silently accepts both HEAD4 and HEAD5.
"""
from __future__ import annotations

import hashlib
import struct

from discovery_audit_sources import catalogue, segmented, wire

equal, parse, require, result = wire.equal, wire.parse, wire.require, wire.result
digest, request, transition, uint = segmented.digest, segmented.request, segmented.transition, segmented.uint

MAX_RESULT = 64 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def object_prefix(authority):
    require(authority["format"] == 4, "strict HEAD4 profile changed")
    return "/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}/objects/".format(**authority["scope"])


def head(raw, path):
    value = catalogue.head_record(raw, path)
    require(type(value["format"]) is int and value["format"] == 4 and len(value["policy"]) <= 4096,
            "strict HEAD4 format/policy bound")
    maximum = value["quota"]["max_bytes"]
    require(maximum is None or maximum <= (2**32 - 2) * 4096 and maximum % 4096 == 0,
            "quota page alignment/bound")
    for window in value["windows"][1:]:
        require(window["count"] == value["retention"]["max_entries"] or
                window["result_bytes"] > value["retention"]["max_result_bytes"] - MAX_RESULT,
                "historical request window was not closed")
    return value


def envelope(raw, key, authority):
    prefix = object_prefix(authority)
    require(key.startswith(prefix) and key == prefix + digest(key[len(prefix):]), "object key escaped complete captured scope")
    require(len(raw) >= 20 and raw[:8] == b"SCAPOBJ2" and sha(raw) == key[len(prefix):], "immutable frame/hash identity")
    metadata_bytes, raw_bytes = struct.unpack_from("<IQ", raw, 8)
    require(metadata_bytes <= 65536 - 20 and len(raw) == 20 + metadata_bytes + raw_bytes, "frame length/bound")
    metadata = parse(raw[20:20 + metadata_bytes])
    require(set(metadata) == {"format", "scope", "payload"} and type(metadata["format"]) is int and metadata["format"] == 2, "object metadata format")
    equal(metadata["scope"], authority["scope"], "object complete Scope differs")
    payload = metadata["payload"]
    require(set(payload) == {"kind", "value"}, "typed payload shape")
    return payload["kind"], payload["value"], raw[20 + metadata_bytes:]


def summary(value):
    require(set(value) == {"first", "last", "count", "result_bytes"}, "child summary fields")
    uint(value["first"], minimum=1); uint(value["last"], minimum=value["first"])
    uint(value["count"], 65536, 1); uint(value["result_bytes"], value["count"] * MAX_RESULT)
    require(value["last"] - value["first"] >= value["count"] - 1, "summary range too small")


class Trees:
    def __init__(self, objects, authority):
        self.objects, self.authority = objects, authority
        self.scope, self.prefix = authority["scope"], object_prefix(authority)
        self.nodes = {}

    def load(self, key, kind):
        require(key in self.objects, "missing full graph dependency: " + key)
        actual, value, raw = envelope(self.objects[key], key, self.authority)
        require(actual == kind, "wrong dependency type")
        return value, raw

    def node(self, digest_value, epoch):
        key = self.prefix + digest(digest_value)
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
                child_value, child_raw = self.load(self.prefix + child["hash"], "index")
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
                key = self.prefix + outcome["result"]
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
        key = self.prefix + digest(root)
        manifest, raw = self.load(key, "manifest")
        require(not raw and set(manifest) == {"page_count", "root"}, "manifest fields")
        pages = uint(manifest["page_count"], 2**32 - 2)
        require(pages * 4096 <= 8 * 1024 * 1024, "fixture native evidence exceeds declared 8 MiB profile")
        dependencies = {key}
        if pages == 0:
            require(manifest["root"] is None, "empty manifest references data")
            return dependencies, b""
        chunks = (pages + 31) // 32
        level = 0
        while chunks > 256**(level + 1): level += 1
        require(level <= 3, "data tree level bound")
        def walk(hash_value, actual_level, first):
            path = self.prefix + digest(hash_value)
            require(path not in dependencies, "repeated data subtree")
            dependencies.add(path)
            node, raw = self.load(path, "node")
            width = (min(max(chunks - first, 0), 256**(actual_level + 1)) + 256**actual_level - 1) // 256**actual_level
            equal({key: node.get(key) for key in ("level", "first_chunk")}, {"level": actual_level, "first_chunk": first}, "data node position/level")
            require(set(node) == {"level", "first_chunk", "children"} and not raw and len(node["children"]) == width, "complete data node extent")
            pieces = []
            for number, child in enumerate(node["children"]):
                start = first + number * 256**actual_level
                if actual_level:
                    pieces.append(walk(child, actual_level - 1, start))
                else:
                    path = self.prefix + digest(child)
                    require(path not in dependencies, "repeated physical chunk")
                    dependencies.add(path)
                    chunk, raw = self.load(path, "chunk")
                    equal(chunk, {"first_page": start * 32 + 1, "bytes": []}, "chunk identity/metadata")
                    require(len(raw) == min(32, pages - start * 32) * 4096, "chunk full page extent")
                    pieces.append(raw)
            return b"".join(pieces)
        image = walk(manifest["root"], level, 0)
        require(len(image) == pages * 4096 and image[:16] == b"SQLite format 3\0" and image[16:18] == b"\x10\0", "native full image/header")
        return dependencies, image
