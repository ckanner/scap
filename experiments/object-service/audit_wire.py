"""Read-only independent public wire witnesses; never imports product/controller code."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(raw):
    def invalid(value):
        raise ValueError("non-finite JSON constant: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def equal(left, right, message):
    require(json.dumps(left, sort_keys=True, ensure_ascii=False, allow_nan=False) ==
            json.dumps(right, sort_keys=True, ensure_ascii=False, allow_nan=False), message)


def b64(value):
    require(isinstance(value, str), "base64 must be text")
    raw = base64.b64decode(value, validate=True)
    require(base64.b64encode(raw).decode() == value, "noncanonical base64")
    return raw


def decimal(value, *, zero=False):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
            "noncanonical decimal")
    number = int(value)
    require((0 if zero else 1) <= number < 2 ** 64, "u64 outside range")
    return number


def fingerprint(statements):
    require(isinstance(statements, list) and 0 < len(statements) <= 65536, "invalid statements")
    data = bytearray(b"SCAPSQL1" + struct.pack("<I", len(statements)))
    for statement in statements:
        require(set(statement) == {"sql", "params"}, "statement fields changed")
        sql = statement["sql"].encode("utf-8", errors="strict")
        require(sql and b"\0" not in sql, "invalid SQL")
        data.extend(struct.pack("<I", len(sql)) + sql)
        parameters = statement["params"]
        require(isinstance(parameters, list) and len(parameters) <= 32766, "invalid parameters")
        data.extend(struct.pack("<I", len(parameters)))
        for value in parameters:
            kind = value["type"]
            if kind == "null":
                require(set(value) == {"type"}, "null fields")
                data.append(0)
            elif kind == "integer":
                require(set(value) == {"type", "value"}, "integer fields")
                text = value["value"]
                require(isinstance(text, str) and re.fullmatch(r"0|-?[1-9][0-9]*", text) is not None,
                        "noncanonical i64")
                number = int(text)
                require(-(2 ** 63) <= number < 2 ** 63, "i64 outside range")
                data.extend(b"\1" + struct.pack("<q", number))
            elif kind == "real":
                require(set(value) == {"type", "bits"} and re.fullmatch(r"[0-9a-f]{16}", value["bits"]), "real fields")
                raw = bytes.fromhex(value["bits"])
                require(math.isfinite(struct.unpack(">d", raw)[0]), "nonfinite parameter")
                data.extend(b"\2" + raw[::-1])
            elif kind == "text":
                require(set(value) == {"type", "value"}, "text fields")
                raw = value["value"].encode("utf-8", errors="strict")
                data.extend(b"\3" + struct.pack("<I", len(raw)) + raw)
            elif kind == "blob":
                require(set(value) == {"type", "base64"}, "blob fields")
                raw = b64(value["base64"])
                data.extend(b"\4" + struct.pack("<I", len(raw)) + raw)
            else:
                raise ValueError("unknown parameter tag")
    return hashlib.sha256(data).hexdigest()


def result(raw):
    require(isinstance(raw, bytes) and len(raw) <= 64 * 1024 * 1024, "result bound")
    position = 0

    def take(count):
        nonlocal position
        require(0 <= count <= len(raw) - position, "truncated result")
        value = raw[position:position + count]
        position += count
        return value

    def number(code):
        return struct.unpack("<" + code, take(struct.calcsize("<" + code)))[0]

    def text():
        return take(number("I")).decode("utf-8", errors="strict")

    def scalar():
        kind = number("B")
        if kind == 0:
            return None
        if kind == 1:
            return number("q")
        if kind == 2:
            value = number("d")
            require(math.isfinite(value), "nonfinite result")
            return value
        if kind == 3:
            return text()
        if kind == 4:
            return take(number("I"))
        raise ValueError("unknown result tag")

    require(take(8) == b"SCAPRES1", "wrong result magic")
    count = number("I")
    require(count <= 65536 and count * 24 <= len(raw) - position, "impossible statement count")
    statements = []
    for _ in range(count):
        columns = number("I")
        require(columns <= 2000 and columns * 4 <= len(raw) - position, "impossible column count")
        names = [text() for _ in range(columns)]
        rows = number("I")
        require((columns != 0 or rows == 0) and rows * columns <= len(raw) - position - 16, "impossible rows")
        statements.append({"columns": names, "rows": [[scalar() for _ in names] for _ in range(rows)],
                           "affected_rows": number("Q"), "last_insert_rowid": number("q")})
    require(position == len(raw), "trailing result bytes")
    return statements


def receipt_hash(receipt, raw):
    require(set(receipt) == {"scope", "request", "sequence", "transition", "data_root", "result_hash"}, "receipt fields")
    scope = receipt["scope"]
    names = ("deployment", "tenant", "database", "incarnation", "generation")
    require(set(scope) == set(names), "scope fields")
    native_scope = {key: decimal(scope[key]) for key in names}
    request = receipt["request"]
    require(set(request) == {"epoch", "id", "principal", "fingerprint"}, "request fields")
    native_request = {key: decimal(request[key]) for key in ("epoch", "id", "principal")}
    native_request["fingerprint"] = request["fingerprint"]
    transition = receipt["transition"]
    require(set(transition) == {"revision", "nonce"}, "transition fields")
    native_transition = {key: decimal(transition[key]) for key in ("revision", "nonce")}
    require(native_transition["nonce"] == native_request["id"], "SQL nonce differs from identity")
    for digest in (request["fingerprint"], receipt["data_root"], receipt["result_hash"]):
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "hash fields")
    metadata = {"format": 2, "scope": native_scope, "payload": {"kind": "result", "value": {
        "request": native_request, "sequence": decimal(receipt["sequence"]), "transition": native_transition,
        "data_root": receipt["data_root"], "bytes": []}}}
    encoded = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(b"SCAPOBJ2" + struct.pack("<IQ", len(encoded), len(raw)) + encoded + raw).hexdigest()


def committed(value):
    require(set(value) == {"state", "receipt", "result"} and value["state"] == "committed", "committed shape")
    raw = b64(value["result"])
    statements = result(raw)
    require(receipt_hash(value["receipt"], raw) == value["receipt"]["result_hash"], "result object digest differs")
    return raw, statements
