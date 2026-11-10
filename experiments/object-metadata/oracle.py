#!/usr/bin/env python3
"""Independent metadata-only real-transport audit. No producer/product imports.

The dedicated M listener is audited from birth through joined handlers. There
is deliberately no HTTP-time-window -> S3-call attribution in this module.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import tarfile
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def independent(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WIRE = independent("scap_metadata_independent_wire", HERE.parent / "object-service/audit_wire.py")
HEAD = independent("scap_metadata_independent_head", HERE.parent / "object-network/head5_audit.py")
BUILD = independent("scap_metadata_independent_build", HERE.parent / "object-network/audit_build.py")
parse, require, b64 = WIRE.parse, WIRE.require, WIRE.b64
NAMES = ("success", "get_unknown", "put_unknown", "stale_412", "permission", "known_quarantine")
WORKERS = {"S": "8101", "M": "8202"}
SCOPES = {name: dict(deployment="1", tenant="7", database=str(2101 + index), incarnation="1", generation="1")
          for index, name in enumerate(NAMES)}
PRINCIPALS = {"writer": "11", "manager": "12", "reader": "13"}
BASE_POLICY = [dict(principal="11", read=True, write=True, admin=False),
               dict(principal="12", read=True, write=False, admin=True),
               dict(principal="13", read=True, write=False, admin=False)]
NEXT_POLICY = [dict(item, write=True) if item["principal"] == "13" else dict(item) for item in BASE_POLICY]
SQL = [dict(sql="CREATE TABLE witness(n INTEGER PRIMARY KEY)", params=[]),
       dict(sql="INSERT INTO witness(n) VALUES(1) RETURNING n", params=[])]
LISTENERS = {"s3-S": ("s3", "S"), "s3-M": ("s3", "M"), "s3-F": ("s3", "F"),
             "http-S": ("http", "S"), "http-M": ("http", "M")}
MAINTENANCE = ("f_quarantine_get", "f_quarantine_corrupt", "f_quarantine_restore")
DEADLINES = dict(ordinary_ms=15000, recovery_ms=30000, s3_ms=10000, client_ms=20000,
                 owner_ms=35000, ready_seconds=20, child_seconds=40, gate_seconds=10, curl_seconds=8, actor_idle_ms=5000)
SHA = re.compile(r"[0-9a-f]{64}")
MAX_FRAME = 2 * 1024 * 1024 + 64 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def equal(left, right, message):
    if isinstance(left, set) or isinstance(right, set):
        require(type(left) is set and type(right) is set and left == right, message)
    else:
        WIRE.equal(left, right, message)


def pack(raw, prefix="body"):
    return {prefix + "_base64": base64.b64encode(raw).decode(), prefix + "_bytes": len(raw), prefix + "_sha256": sha(raw)}


def raw_bytes(row, prefix="body", maximum=MAX_FRAME):
    raw = b64(row[prefix + "_base64"])
    require(type(row[prefix + "_bytes"]) is int and 0 <= row[prefix + "_bytes"] <= maximum and
            len(raw) == row[prefix + "_bytes"] and sha(raw) == row[prefix + "_sha256"],
            "complete raw bytes/length/SHA disagree: " + prefix)
    return raw


def stamp(row):
    value = row["monotonic_ns"]
    require((type(value) is int and value > 0) or
            (type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) is not None), "invalid observation timestamp")
    return int(value)


def only(values, message):
    require(len(values) == 1, message)
    return values[0]


def rows(directory, filename, *, numbered=True, node=False):
    raw = (Path(directory) / filename).read_bytes()
    require(raw and raw.endswith(b"\n"), "truncated/empty raw ledger: " + filename)
    values = [parse(line) for line in raw.splitlines()]
    for index, value in enumerate(values, 1):
        require(type(value) is dict and type(value.get("schema")) is int and value["schema"] == 1,
                "ledger schema changed: " + filename)
        if numbered:
            require(type(value.get("sequence")) is int and value["sequence"] == index, "ledger sequence gap: " + filename)
        require(type(value["monotonic_ns"]) is (str if node else int), "timestamp representation changed: " + filename)
        stamp(value)
        if index > 1:
            require(stamp(values[index - 2]) <= stamp(value), "ledger clocks reversed: " + filename)
    return values


def head_path(name):
    return "/scap-test/scap-object/v1/1/7/" + SCOPES[name]["database"] + "/head"


def object_prefix(name):
    return HEAD.object_prefix({key: int(value) for key, value in SCOPES[name].items()}, 1)


def tracked(name):
    return {"scope": SCOPES[name], "request": {"epoch": "1", "id": "1", "principal": "11", "fingerprint": WIRE.fingerprint(SQL)},
            "statements": SQL}


def command_table():
    """Independent offered-program specification, never loaded from fixture_spec."""
    commands = []
    def add(name, worker, scope, operation, caller="manager", status=200, **extra):
        commands.append(dict(id=name, worker=worker, scope=scope, operation=operation,
                             caller=caller, http_status=status, **extra))
    for index, name in enumerate(NAMES):
        nonce = 10000 + 10 * index
        add("s_" + name + "_create", "S", name, "create", "writer", nonce=str(nonce))
        add("s_" + name + "_activate", "S", name, "activate", "writer", revision="1", nonce=str(nonce + 1), expected_worker="8101")
        add("s_" + name + "_execute", "S", name, "execute", "writer")
        add("s_" + name + "_policy", "S", name, "policy", "writer", revision="3", nonce=str(nonce + 2), permissions=BASE_POLICY)
    add("m_success_status_before", "M", "success", "status")
    add("m_success_takeover", "M", "success", "takeover", revision="4", nonce="20001", expected_worker="8202")
    add("m_success_policy", "M", "success", "policy", revision="5", nonce="20002", permissions=NEXT_POLICY)
    add("m_success_status_after", "M", "success", "status")
    add("m_get_unknown_takeover", "M", "get_unknown", "takeover", status=503, revision="4", nonce="21001", expected_worker="8202")
    add("o_get_unknown_status", "S", "get_unknown", "status")
    add("m_put_unknown_policy", "M", "put_unknown", "policy", status=503, revision="4", nonce="22001", permissions=NEXT_POLICY)
    add("o_put_unknown_status", "S", "put_unknown", "status")
    add("m_stale_takeover", "M", "stale_412", "takeover", status=409, revision="4", nonce="23001", expected_worker="8202")
    add("o_stale_policy", "S", "stale_412", "policy", revision="4", nonce="23002", permissions=NEXT_POLICY)
    add("m_permission_takeover", "M", "permission", "takeover", "reader", 403, revision="4", nonce="24001", expected_worker="8202")
    add("m_permission_policy", "M", "permission", "policy", "reader", 403, revision="4", nonce="24002", permissions=NEXT_POLICY)
    add("o_permission_status", "S", "permission", "status")
    add("m_quarantine_bad_status", "M", "known_quarantine", "status", status=409)
    add("m_quarantine_repaired_status", "M", "known_quarantine", "status")
    add("m_quarantine_takeover", "M", "known_quarantine", "takeover", status=409, revision="4", nonce="25001", expected_worker="8202")
    add("m_quarantine_policy", "M", "known_quarantine", "policy", status=409, revision="4", nonce="25002", permissions=NEXT_POLICY)
    return commands


COMMANDS = command_table()
BY_ID = {item["id"]: item for item in COMMANDS}


def action(command):
    spec = BY_ID[command] if isinstance(command, str) else command
    result = {"version": 1, "scope": SCOPES[spec["scope"]], "operation": spec["operation"]}
    for source, target in (("revision", "expected_revision"), ("nonce", "nonce"), ("expected_worker", "expected_worker_instance"),
                           ("permissions", "permissions")):
        if source in spec:
            result[target] = spec[source]
    if spec["operation"] == "execute":
        result.update({key: value for key, value in tracked(spec["scope"]).items() if key != "scope"})
    return result


def expected_code(name):
    return ("UNKNOWN" if name in ("m_get_unknown_takeover", "m_put_unknown_policy") else
            "CONFLICT" if name == "m_stale_takeover" else
            "DENIED" if name.startswith("m_permission_") else "CORRUPT")


def status_from_head(head):
    return {"scope": {key: str(value) for key, value in head["scope"].items()},
            **{key: str(head[key]) for key in ("head_serial", "revision", "sequence", "owner_epoch", "owner_instance", "auth_epoch", "request_epoch")},
            "storage": {"active_generation": "1", "allocated_through": "1", "plan": None, "sweep": None},
            "active": head["active"], "lifecycle": head["lifecycle"],
            "max_bytes": None if head["quota"]["max_bytes"] is None else str(head["quota"]["max_bytes"]),
            "transition": {key: str(value) for key, value in head["transition"].items()},
            "retention": {"max_entries": head["retention"]["max_entries"],
                          "max_result_bytes": str(head["retention"]["max_result_bytes"]),
                          "oldest_epoch": str(head["windows"][-1]["epoch"] if head["windows"] else head["request_epoch"])}}


def head(raw, name):
    require(len(raw) <= 256 * 1024, "HEAD exceeds format byte bound")
    value = parse(raw)
    HEAD.validate(value)
    equal(value["scope"], {key: int(number) for key, number in SCOPES[name].items()}, "authority changed complete Scope")
    return value


def frame(raw, path):
    require(20 <= len(raw) <= MAX_FRAME and raw[:8] == b"SCAPOBJ2" and sha(raw) == path.rsplit("/", 1)[-1],
            "immutable original frame/hash differs")
    metadata_length, raw_length = struct.unpack_from("<IQ", raw, 8)
    require(metadata_length <= 2 * 1024 * 1024 and raw_length <= 64 * 1024 * 1024 and
            20 + metadata_length + raw_length == len(raw), "immutable frame extent/bounds differ")
    metadata = parse(raw[20:20 + metadata_length])
    require(type(metadata) is dict and set(metadata) == {"format", "scope", "payload"} and
            type(metadata["format"]) is int and metadata["format"] == 2, "immutable metadata format differs")
    prefix = HEAD.object_prefix(metadata["scope"], 1)
    require(path == prefix + sha(raw) and metadata["scope"] in
            [{key: int(value) for key, value in scope.items()} for scope in SCOPES.values()], "immutable Scope/physical namespace differs")
    payload = metadata["payload"]
    require(type(payload) is dict and set(payload) == {"kind", "value"} and payload["kind"] in
            {"chunk", "node", "manifest", "index", "result"}, "unknown immutable payload kind")
    return payload, raw[20 + metadata_length:]


def endpoint(value, path=""):
    require(type(value) is str, "endpoint is not text")
    parsed = urlsplit(value)
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port is not None and
            parsed.username is None and parsed.password is None and parsed.path == path and not parsed.query and not parsed.fragment,
            "fixture endpoint escaped dedicated local authority")
    return parsed.netloc


def load_configuration(directory):
    directory = Path(directory)
    config = parse((directory / "metadata-configuration.json").read_bytes())
    equal(set(config), {"schema", "workers", "scopes", "endpoints", "s3_endpoints", "credential_sha256", "backend", "services", "private"},
          "public configuration fields changed")
    require(type(config["schema"]) is int and config["schema"] == 1, "configuration schema changed")
    equal(config["workers"], WORKERS, "configured workers changed")
    equal(config["scopes"], SCOPES, "configured full Scopes changed")
    equal(set(config["endpoints"]), {"S", "M"}, "HTTP endpoint denominator changed")
    equal(set(config["s3_endpoints"]), {"S", "M", "F"}, "S3 endpoint denominator changed")
    addresses = [endpoint(value, "/v1") for value in config["endpoints"].values()]
    addresses += [endpoint(value) for value in config["s3_endpoints"].values()]
    addresses.append(endpoint(config["backend"]["endpoint"]))
    require(len(set(addresses)) == 6, "dedicated HTTP/S3/backend listeners alias")
    require(set(config["backend"]) == {"endpoint", "access_key_sha256"}, "backend fields changed")
    WIRE.sha256_text(config["backend"]["access_key_sha256"])
    equal(set(config["credential_sha256"]), set(PRINCIPALS), "credential-role denominator changed")
    require(len(set(config["credential_sha256"].values())) == 3, "roles share one credential")
    for digest in config["credential_sha256"].values():
        WIRE.sha256_text(digest)
    equal(set(config["services"]), {"S", "M"}, "service denominator changed")
    private = config["private"]
    require(set(private) == {"path", "device", "inode"} and Path(private["path"]).is_absolute() and
            Path(private["path"]).is_relative_to(Path("/tmp")) and ".." not in Path(private["path"]).parts and
            Path(private["path"]).name.startswith("scap-metadata-private-") and
            all(type(private[key]) is int and private[key] > 0 for key in ("device", "inode")), "private runtime identity changed")
    configs = {}
    for worker in ("S", "M"):
        service = config["services"][worker]
        require(set(service) == {"configuration_file", "backend_endpoint", "worker_instance", "cache_directory"}, "service binding fields changed")
        equal([service["configuration_file"], service["worker_instance"]],
              ["service-" + worker + ".json", WORKERS[worker]], "service/listener/worker binding changed")
        addresses.append(endpoint(service["backend_endpoint"]))
        require(".." not in Path(service["cache_directory"]).parts and Path(service["cache_directory"]).is_relative_to(Path(private["path"])),
                "cache escaped private runtime")
        original = (directory / service["configuration_file"]).read_bytes()
        value = parse(original)
        require(type(value["version"]) is int and value["version"] == 1 and value["worker_instance"] == WORKERS[worker] and
                value["listen"] == endpoint(service["backend_endpoint"]) and value["cache_directory"] == service["cache_directory"] and
                value["s3"]["endpoint"] == config["s3_endpoints"][worker],
                "actual daemon configuration differs from authority binding")
        require(value["admission"]["control_workers"] == 1 and value["admission"]["timeout_ms"] == 15000 and
                value["admission"]["recovery_timeout_ms"] == 30000 and value["s3"]["timeout_ms"] == 10000,
                "control Engine count/original service deadlines changed")
        require(value["s3"]["bucket"] == "scap-test" and value["s3"]["region"] == "us-east-1" and value["s3"]["allow_http"] is True,
                "actual backend profile changed")
        require(set(value["credentials"][0]) <= {"sha256", "deployment", "tenant", "principal", "provision", "deployment_inventory"},
                "credential recorded plaintext/unknown fields")
        actual_roles = {}
        for item in value["credentials"]:
            require(item["principal"] not in actual_roles, "duplicate credential principal")
            actual_roles[item["principal"]] = item
        require(set(actual_roles) == set(PRINCIPALS.values()), "service credential role count changed")
        for role, principal in PRINCIPALS.items():
            item = actual_roles[principal]
            equal({key: item[key] for key in ("sha256", "deployment", "tenant", "principal", "provision")},
                  {"sha256": config["credential_sha256"][role], "deployment": "1", "tenant": "7", "principal": principal,
                   "provision": role == "writer"}, "actual credential authority changed")
            require(item.get("deployment_inventory", False) is False, "unexpected inventory authority")
        configs[worker] = {"value": value, "sha256": sha(original)}
    require(config["services"]["S"]["cache_directory"] != config["services"]["M"]["cache_directory"], "services share compute cache")
    require(len(set(addresses)) == 8, "native daemon listener aliases a relay/backend")
    return config, configs


def exchange_rows(trace, channel):
    """Complete handler and original request/forward/reply/terminal bijections."""
    is_s3 = channel == "s3"
    serial_field = "request_serial" if is_s3 else "http_serial"
    events = (("object_request", "object_forwarded", "object_response", "object_response_delivered") if is_s3 else
              ("http_request", "http_forwarded", "http_response", "http_delivered"))
    allowed = set(events) | {"handler_started", "handler_finished"}
    if is_s3:
        allowed.add("object_response_suppressed")
    require(all(row["event"] in allowed for row in trace), "unplanned proxy event/failure")
    handlers, grouped = defaultdict(list), defaultdict(list)
    for row in trace:
        listener = row["listener_id"]
        require(listener in LISTENERS and LISTENERS[listener] == (channel, row["worker"]), "proxy listener identity changed")
        require(re.fullmatch(re.escape(listener) + r":[1-9][0-9]*", row["handler_id"]) is not None, "invalid original handler identity")
        handlers[row["handler_id"]].append(row)
        if serial_field in row:
            require(type(row[serial_field]) is int and row[serial_field] > 0, "invalid proxy request serial")
            grouped[row[serial_field]].append(row)
    require(sorted(grouped) == list(range(1, len(grouped) + 1)), "proxy request serial inventory is incomplete")
    result = []
    request_fields = (serial_field, "listener_id", "handler_id", "worker", "method", "path",
                      "request_body_base64", "request_body_bytes", "request_body_sha256")
    request_fields += ("if_match", "if_none_match", "signing") if is_s3 else ("command", "credential_sha256")
    response_fields = ("status", "response_body_base64", "response_body_bytes", "response_body_sha256", "response_origin")
    response_fields += ("etag",) if is_s3 else ("response_headers",)
    for serial, records in grouped.items():
        kinds = [row["event"] for row in records]
        terminal = "object_response_suppressed" if "object_response_suppressed" in kinds else events[-1]
        equal(kinds, [*events[:3], terminal], "missing/duplicate/unexplained original exchange")
        request, forwarded, response, delivered = records
        for row in records:
            equal({key: row[key] for key in request_fields}, {key: request[key] for key in request_fields}, "proxy rebound original request")
            raw_bytes(row, "request_body")
        for row in (response, delivered):
            raw_bytes(row, "response_body")
        equal({key: delivered[key] for key in response_fields}, {key: response[key] for key in response_fields},
              "delivery differs from original backend response")
        require(stamp(request) < stamp(forwarded) < stamp(response) <= stamp(delivered), "proxy original event order changed")
        require(response["response_origin"] == ("backend" if is_s3 else "service"), "fabricated relay reply")
        require(type(response["status"]) is int and 100 <= response["status"] <= 599, "invalid backend status")
        if is_s3 and response["status"] == 200:
            require(type(response["etag"]) is str and response["etag"], "successful exact backend response lacks ETag")
        if terminal == "object_response_suppressed":
            require(delivered["reason"] == "explicit_response_loss" and response["status"] == 200, "unexplained response loss")
        chain = handlers[request["handler_id"]]
        start = only([row for row in chain if row["event"] == "handler_started"], "handler start denominator")
        end = only([row for row in chain if row["event"] == "handler_finished"], "handler end denominator")
        require(start["channel"] == end["channel"] == channel and end["failed"] is False and
                stamp(start) <= stamp(request) <= stamp(delivered) <= stamp(end), "handler failed or escaped its owned lifetime")
        result.append({"request": request, "forwarded": forwarded, "response": response, "terminal": delivered,
                       "handler_start": start, "handler_finish": end})
    equal(Counter(item["request"]["handler_id"] for item in result),
          Counter({handler: 1 for handler in handlers}),
          "proxy handler hidden or reused outside complete request inventory")
    for listener in {value["listener_id"] for value in trace}:
        ids = sorted(int(key.rsplit(":", 1)[1]) for key in handlers if key.startswith(listener + ":"))
        require(ids == list(range(1, len(ids) + 1)), "handler admission denominator has a gap")
    return result, handlers


def s3_exchanges(trace, config):
    exchanges, handlers = exchange_rows(trace, "s3")
    for item in exchanges:
        request, response = item["request"], item["response"]
        method, path = request["method"], request["path"]
        require(method in ("GET", "PUT") and type(path) is str and "?" not in path and "#" not in path,
                "unplanned S3 method/LIST/path")
        require(path in {head_path(name) for name in NAMES} or any(re.fullmatch(re.escape(object_prefix(name)) + r"[0-9a-f]{64}", path)
                for name in NAMES), "S3 request escaped exact Scope/physical generation")
        raw = raw_bytes(request, "request_body")
        if method == "GET":
            require(raw == b"" and request["if_match"] is None and request["if_none_match"] is None, "GET changed original body/conditions")
            require(response["status"] in (200, 404), "unplanned GET backend status")
        else:
            require((request["if_none_match"] == "*" and request["if_match"] is None) or
                    (request["if_none_match"] is None and type(request["if_match"]) is str and request["if_match"]),
                    "unconditional/ambiguous PUT")
            require(response["status"] in (200, 412), "unplanned PUT backend status")
        signing = request["signing"]
        require(set(signing) == {"algorithm", "access_key_sha256", "credential_scope", "signed_headers", "signature_sha256", "host", "date", "payload_sha256"},
                "incomplete signed request witness")
        require(signing["algorithm"] == "AWS4-HMAC-SHA256" and signing["access_key_sha256"] == config["backend"]["access_key_sha256"] and
                signing["host"] == endpoint(config["s3_endpoints"][request["worker"]]) and
                signing["payload_sha256"] == sha(raw), "signed S3 request body/authority differs")
        require(re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", signing["date"]) and
                signing["credential_scope"] == signing["date"][:8] + "/us-east-1/s3/aws4_request", "SigV4 scope/date changed")
        WIRE.sha256_text(signing["signature_sha256"])
        headers = signing["signed_headers"]
        require(type(headers) is list and headers == sorted(set(headers)) and
                {"host", "x-amz-date", "x-amz-content-sha256"} <= set(headers), "signed header inventory changed")
    return exchanges, handlers


def projected_exchange(item):
    return {"source": {"file": "s3.jsonl", "sequences": [row["sequence"] for row in
             (item["request"], item["forwarded"], item["response"], item["terminal"])],
             "request_serial": item["request"]["request_serial"], "handler_id": item["request"]["handler_id"]},
            **{key: deepcopy(item[key]) for key in ("request", "forwarded", "response", "terminal")}}


class SemanticFailure(ValueError):
    def __init__(self, rule, message):
        self.rule = rule
        super().__init__(rule + ": " + message)


def rule(condition, name, message):
    if not condition:
        raise SemanticFailure(name, message)


def metadata_semantics(projection):
    """Pure claim verifier, also used by explicitly scoped semantic controls.

    Actual inputs come only from the independently audited raw file projection.
    It is NOT an alternate entry point for accepting unaudited actual evidence.
    """
    calls, stream = projection["calls"], projection["stream"]
    for call in calls:
        rule(call["request_body"].get("operation") in ("status", "takeover", "policy"), "M_NON_METADATA", "M received a non-metadata operation")
    for item in stream:
        request = item["request"]
        if "/objects/" in request["path"]:
            raw = raw_bytes(item["response"], "response_body") if request["method"] == "GET" else raw_bytes(request, "request_body")
            frame(raw, request["path"])
            if stamp(request) > projection["last_http_response_ns"]:
                raise SemanticFailure("M_TAIL_OBJECT_IO", "payload I/O appeared in the joined listener tail")
            raise SemanticFailure("M_OBJECT_" + request["method"], "metadata stream touched a valid immutable frame")
        rule(request["path"] in {head_path(name) for name in NAMES} and request["method"] in ("GET", "PUT"),
             "M_AUTHORITY", "M escaped the declared HEAD set")
        if request["path"] == head_path("permission"):
            rule(request["method"] == "GET", "M_PERMISSION", "permission denial still published a HEAD")
    for call in calls:
        name = call["command"]
        if name.startswith("m_permission_"):
            rule(call["credential_sha256"] == projection["credentials"]["reader"] and call["status"] == 403 and
                 call["outcome"] == {"ok": False, "error": {"name": "RemoteError", "code": "DENIED"}},
                 "M_PERMISSION", "DENIED input/outcome changed")
        elif name in ("m_get_unknown_takeover", "m_put_unknown_policy"):
            rule(call["status"] == 503 and call["outcome"] == {"ok": False, "error": {"name": "UnknownError", "code": "UNKNOWN"}},
                 "M_UNKNOWN_OUTCOME", "backend effect was substituted for the original caller UNKNOWN")
        elif name in ("m_quarantine_bad_status", "m_quarantine_takeover", "m_quarantine_policy"):
            rule(call["status"] == 409 and call["outcome"] == {"ok": False, "error": {"name": "RemoteError", "code": "CORRUPT"}},
                 "M_KNOWN_QUARANTINE", "repair silently cleared the resident handle's known failure")
    puts = [item for item in stream if item["request"]["method"] == "PUT"]
    rule(len(puts) == 4, "M_PUBLICATION_ATTEMPT_COUNT", "metadata publication was retried/rebuilt or omitted")
    for item in puts:
        request = item["request"]
        name = next(name for name in NAMES if request["path"] == head_path(name))
        candidate = head(raw_bytes(request, "request_body"), name)
        expected = projection["bases"][name]
        if name == "success" and candidate["transition"]["nonce"] == 20002:
            expected = projection["success_takeover"]
        rule(request["if_match"] == expected["etag"] and request["if_none_match"] is None,
             "M_ORIGINAL_ETAG", "candidate rebound its original exact HEAD condition")
    expected_stream = [("success", "GET", 200), ("success", "GET", 200), ("success", "PUT", 200),
                       ("success", "GET", 200), ("success", "PUT", 200), ("success", "GET", 200),
                       ("get_unknown", "GET", 200), ("put_unknown", "GET", 200), ("put_unknown", "PUT", 200),
                       ("stale_412", "GET", 200), ("stale_412", "PUT", 412), ("permission", "GET", 200),
                       ("permission", "GET", 200), *( ("known_quarantine", "GET", 200) for _ in range(4))]
    equal([(item["request"]["path"], item["request"]["method"], item["response"]["status"]) for item in stream],
          [(head_path(name), method, status) for name, method, status in expected_stream], "M complete lifetime I/O program changed")
    equal([call["command"] for call in calls], [item["id"] for item in COMMANDS if item["worker"] == "M"], "M command denominator/order changed")
    for call in calls:
        spec = BY_ID[call["command"]]
        equal(call["request_body"], action(spec), "M original request/nonce/guard changed")
        equal(call["credential_sha256"], projection["credentials"][spec["caller"]], "M changed authenticated principal")
        require(call["status"] == spec["http_status"], "M outcome status changed")
    return {"http_requests": 13, "head_gets": 13, "head_put_attempts": 4, "head_put_accepted": 3,
            "head_put_conflicts": 1, "immutable_io": 0, "attribution": "entire dedicated M listener lifecycle"}


def plan_proof(directory):
    value = parse((Path(directory) / "metadata-plan.json").read_bytes())
    expected = {"schema": 1, "profile": "metadata-head-only-real-transport-v1", "workers": WORKERS,
                "scopes": SCOPES, "seed_scopes": list(NAMES), "principals": PRINCIPALS,
                "base_policy": BASE_POLICY, "next_policy": NEXT_POLICY,
                "seed_sql": [item["sql"] for item in SQL], "seed_nonce_base": 10000,
                "deadlines": DEADLINES, "commands": COMMANDS,
                "maintenance": [{"id": name, "method": "GET" if index == 0 else "PUT", "scope": "known_quarantine"}
                                for index, name in enumerate(MAINTENANCE)],
                "limits": {"proxy_body_bytes": 4 * 1024 * 1024, "http_request_bytes": 65536, "node_line_bytes": 1024 * 1024},
                "expected": {"M_http": 13, "S_http": 28, "total_http": 41, "M_head_get": 13, "M_head_put": 4, "F_s3": 3, "seed_ack": 6},
                "claims": {"aws_standard": "NOT_RUN", "production_slo": "NOT_RUN", "native_payload_health_of_M": "NOT_PROVED",
                           "internal_dispatch_times": "NOT_OBSERVED"}}
    equal(value, expected, "offered plan differs from independent finite contract")
    return sha((Path(directory) / "metadata-plan.json").read_bytes())


def node_proof(directory, events):
    directory = Path(directory)
    captured = []
    for event in events:
        if event["event"] == "node_event":
            raw = raw_bytes(event, "raw", 1024 * 1024)
            require(raw.endswith(b"\n") and raw.count(b"\n") == 1 and stamp(parse(raw)) < stamp(event), "Node stdout line capture changed")
            captured.append(raw)
    equal((directory / "metadata-node.jsonl").read_bytes(), b"".join(captured), "fsynced Node trace differs from captured stdout")
    trace = rows(directory, "metadata-node.jsonl", node=True)
    require(all(type(row.get("node")) is int and row["node"] == 1 and row["event"] in
                {"hello", "command_started", "fetch_authorization", "saved_request", "command_finished", "finished"}
                for row in trace), "Node event inventory changed")
    require(trace[0]["event"] == "hello" and trace[-1]["event"] == "finished", "missing original Node start/end")
    require(Counter(row["event"] for row in trace)["hello"] == Counter(row["event"] for row in trace)["finished"] == 1,
            "repeated Node lifetime")
    equal({key: trace[-1][key] for key in ("commands", "http_attempts")}, {"commands": 41, "http_attempts": 41}, "Node hid input/retry denominator")
    offered = [row for row in events if row["event"] == "operator_command"]
    equal([row["id"] for row in offered], [row["id"] for row in COMMANDS] + ["shutdown"], "original stdin command order/denominator changed")
    for row in offered:
        raw = raw_bytes(row, "raw", 65536)
        require(raw.endswith(b"\n") and raw.count(b"\n") == 1, "stdin input is not a complete original line")
        equal(parse(raw), {"id": row["id"]}, "stdin added an unplanned argument")
    operations, saved = {}, {}
    grouped = defaultdict(list)
    for row in trace[1:-1]:
        require(row.get("command") in BY_ID, "unoffered Node operation")
        grouped[row["command"]].append(row)
    require(set(grouped) == set(BY_ID), "Node input denominator differs")
    for spec, original in zip(COMMANDS, offered):
        name = spec["id"]
        selected = grouped[name]
        start = only([row for row in selected if row["event"] == "command_started"], "Node command start count")
        finish = only([row for row in selected if row["event"] == "command_finished"], "Node command end count")
        auth = only([row for row in selected if row["event"] == "fetch_authorization"], "original Fetch authorization count")
        require(type(finish["ok"]) is bool and selected[0] is start and selected[-1] is finish and
                stamp(original) < stamp(start) < stamp(auth) < stamp(finish) and
                stamp(finish) - stamp(start) <= 40 * 10**9, "SDK command escaped original input/bound")
        require(set(finish) == {"schema", "sequence", "monotonic_ns", "event", "node", "command", "call_id", "ok", "value" if finish["ok"] else "error"},
                "SDK terminal event omitted/added outcome fields")
        if not finish["ok"]:
            require(set(finish["error"]) == {"name", "code"}, "SDK error contains unbounded private text")
        require(auth["worker"] == spec["worker"], "Fetch authorization changed endpoint worker")
        operations[name] = {"start": start, "finish": finish, "authorization": auth, "offered": original}
        records = [row for row in selected if row["event"] == "saved_request"]
        if spec["operation"] == "execute":
            record = only(records, "seed request save count")
            filename = "request-" + spec["scope"] + ".json"
            equal([record["scope"], record["file"]], [spec["scope"], filename], "saved original request identity changed")
            raw = raw_bytes(record, "raw", 65536)
            equal((directory / filename).read_bytes(), raw, "saved original request file changed")
            equal(parse(raw), tracked(spec["scope"]), "saved request changed fingerprint/Scope/SQL identity")
            require(stamp(start) < stamp(record) < stamp(auth), "SQL sent before saving its original identity")
            saved[spec["scope"]] = record
        else:
            require(not records, "non-SQL operation saved a replacement request")
    require(max(stamp(value["finish"]) for value in operations.values()) < stamp(offered[-1]) < stamp(trace[-1]), "shutdown preceded completed original commands")
    return trace, operations, saved


def result_sdk(raw, receipt):
    expected = [{"columns": [], "rows": [], "affected_rows": 0, "last_insert_rowid": 0},
                {"columns": ["n"], "rows": [[1]], "affected_rows": 1, "last_insert_rowid": 1}]
    equal(WIRE.result(raw), expected, "fixed seed SQL result/metadata changed")
    return {"state": "committed", "receipt": receipt, "rawResult": pack(raw),
            "result": {"statements": [{"columns": item["columns"],
                        "rows": [[{"integer": str(value)} for value in row] for row in item["rows"]],
                        "affectedRows": {"integer": str(item["affected_rows"])},
                        "lastInsertRowid": {"integer": str(item["last_insert_rowid"])}} for item in expected]}}


def http_proof(directory, trace, operations, config, node):
    relays, handlers = exchange_rows(trace, "http")
    equal(Counter(item["request"]["worker"] for item in relays), Counter({"S": 28, "M": 13}), "whole HTTP listener denominator changed")
    by_command = {}
    for item in relays:
        request = item["request"]
        name = request["command"]
        require(name in BY_ID and name not in by_command, "unoffered/repeated actual HTTP request")
        require(request["method"] == "POST" and request["path"] == "/v1" and request["worker"] == BY_ID[name]["worker"], "HTTP method/path/worker changed")
        equal(parse(raw_bytes(request, "request_body", 65536)), action(name), "actual HTTP input differs from fixed command")
        by_command[name] = item
    require(set(by_command) == set(BY_ID), "HTTP relay omitted an offered input")
    ledger = rows(directory, "http-client-ledger.jsonl", numbered=False, node=True)
    require(all(row.get("phase") == "metadata" and row["event"] in {"client_process_hello", "http_request", "http_response"} for row in ledger),
            "original Fetch ledger contains failure/unplanned activity")
    hello = only([row for row in ledger if row["event"] == "client_process_hello"], "Fetch process identity missing")
    require(ledger[0] is hello and hello["pid_source"] == node[0]["pid_source"] == "node_process.pid" and
            hello["self_pid"] == node[0]["self_pid"] and type(hello["self_pid"]) is int and hello["self_pid"] > 0, "Node/Fetch process identities differ")
    calls, requests = {}, []
    for row in ledger[1:]:
        name = row["client"]
        require(name in BY_ID, "unoffered original Fetch")
        raw = b64(row["body"])
        require(sha(raw) == row["body_sha256"], "frozen client ledger byte digest changed")
        if row["event"] == "http_request":
            require(name not in calls, "SDK retried the same command")
            serial = len(requests) + 1
            equal(row["call_id"], f"metadata:{hello['self_pid']}:{serial}", "Fetch original attempt ordinal changed")
            spec = BY_ID[name]
            require(row["url"] == config["endpoints"][spec["worker"]] and row["method"] == "POST", "Fetch destination changed")
            admission = "recovery" if spec["operation"] == "activate" else "data" if spec["operation"] in ("create", "execute") else "control"
            equal(row["headers"], {"content-type": "application/json", "x-scap-admission": admission}, "SDK admission/auth boundary changed")
            equal(parse(raw), action(spec), "Fetch body differs from frozen input")
            calls[name] = {"request": row, "body": raw}
            requests.append(name)
        else:
            require(name in calls and "response" not in calls[name], "missing/duplicate original Fetch response")
            call = calls[name]
            require(row["call_id"] == call["request"]["call_id"] and stamp(call["request"]) < stamp(row), "Fetch terminal rebound original invocation")
            require(row["headers"]["content-type"].split(";")[0].strip().lower() == "application/json", "non-JSON API reply")
            call["response"], call["response_body"], call["envelope"] = row, raw, parse(raw)
    equal(requests, [item["id"] for item in COMMANDS], "original Fetch order/denominator changed")
    for name, call in calls.items():
        require("response" in call, "original Fetch has no complete reply")
        spec, operation, relay = BY_ID[name], operations[name], by_command[name]
        require(stamp(operation["start"]) < stamp(operation["authorization"]) <= stamp(call["request"]) < stamp(relay["request"]) and
                stamp(relay["response"]) < stamp(call["response"]) < stamp(operation["finish"]), "original Fetch/relay/SDK ordering changed")
        equal(raw_bytes(relay["request"], "request_body"), call["body"], "relay received other original request bytes")
        equal(raw_bytes(relay["response"], "response_body"), call["response_body"], "Fetch did not receive original service body")
        require(relay["response"]["status"] == call["response"]["status"] == spec["http_status"], "service/Fetch status differs from command")
        credential = config["credential_sha256"][spec["caller"]]
        require(relay["request"]["credential_sha256"] == operation["authorization"]["credential_sha256"] == credential, "actual bearer principal differs from fixed role")
        require(operation["finish"]["call_id"] == call["request"]["call_id"], "SDK outcome rebound another Fetch")
        envelope = call["envelope"]
        ok = spec["http_status"] == 200
        require(type(envelope["ok"]) is bool and envelope["ok"] is ok and operation["finish"]["ok"] is ok and
                set(envelope) == ({"ok", "value"} if ok else {"ok", "error"}), "API/SDK outcome envelope changed")
        if ok:
            value = envelope["value"]
            if spec["operation"] == "execute":
                raw, _ = WIRE.committed(value)
                equal(value["receipt"]["scope"], SCOPES[spec["scope"]], "SQL ACK belongs to another Scope")
                equal(value["receipt"]["request"], tracked(spec["scope"])["request"], "SQL ACK changed original request")
                equal([value["receipt"]["sequence"], value["receipt"]["transition"]], ["1", {"revision": "3", "nonce": "1"}], "SQL ACK transition changed")
                equal(operation["finish"]["value"], result_sdk(raw, value["receipt"]), "SDK SQL result differs from original complete receipt/bytes")
            else:
                equal(operation["finish"]["value"], value, "SDK status differs from raw HTTP reply")
        else:
            code = expected_code(name)
            equal(envelope["error"], {"code": code, "message": code}, "unexpected product rejection body")
            equal(operation["finish"]["error"], {"name": "UnknownError" if code == "UNKNOWN" else "RemoteError", "code": code}, "SDK lost original remote/UNKNOWN distinction")
        call.update(operation=operation, relay=relay)
    return calls, handlers


def observer_proof(directory, calls):
    trace = rows(directory, "http-client-transport.jsonl", node=True)
    require(all(row.get("phase") == "metadata" for row in trace), "transport sidecar changed phase")
    allowed = {"observer_started", "observer_stopped", "fetch_started", "request_created", "socket_observed",
               "request_send_headers", "request_response_headers", "request_body_complete", "fetch_response_headers",
               "fetch_body_started", "fetch_body_complete", "call_observation_finished", "socket_end", "socket_close", "socket_error"}
    require(all(row["event"] in allowed for row in trace), "transport sidecar incomplete/failed/unplanned")
    require(trace[0]["event"] == "observer_started" and trace[-1]["event"] == "observer_stopped" and
            sum(row["event"] == "observer_started" for row in trace) == sum(row["event"] == "observer_stopped" for row in trace) == 1,
            "transport observer lifetime changed")
    equal(trace[0]["limits"], {"callEvents": 64, "callRequests": 8, "callConnections": 8, "connectionEvents": 16,
                               "activeConnections": 128, "pendingEvents": 1024}, "frozen observer bounds changed")
    require(trace[-1]["observation_status"] == "RECORDED" and type(trace[-1]["remaining_connections"]) is int and
            0 <= trace[-1]["remaining_connections"] <= 128, "observer final completeness missing")
    by_call, connections = defaultdict(list), defaultdict(list)
    for row in trace:
        if row["event"] in {"observer_started", "observer_stopped"}:
            require("call_id" not in row and "connection_id" not in row, "observer boundary borrowed an operation identity")
        elif row["event"].startswith("socket_"):
            require("connection_id" in row and "call_id" not in row, "socket observation lacks its own connection identity")
            connections[row["connection_id"]].append(row)
        else:
            require("call_id" in row, "transport request observation lacks its original call identity")
            by_call[row["call_id"]].append(row)
    equal(set(by_call), {call["request"]["call_id"] for call in calls.values()}, "observer call inventory differs from actual Fetch")
    bound = {}
    for call in calls.values():
        call_id = call["request"]["call_id"]
        selected = by_call[call_id]
        event = lambda name: only([row for row in selected if row["event"] == name], "observer original event count: " + name)
        first, last = event("fetch_started"), event("call_observation_finished")
        created, sent, response, body = event("request_created"), event("request_send_headers"), event("request_response_headers"), event("request_body_complete")
        fetch_headers, body_start, body_end = event("fetch_response_headers"), event("fetch_body_started"), event("fetch_body_complete")
        require(len(selected) == 9 and selected[0] is first and selected[-1] is last, "observer repeated/hidden native HTTP request")
        request_id = call_id + ":request:1"
        require(all(row["request_id"] == request_id for row in (created, sent, response, body)), "transport request identity rebound")
        require(response["status"] == fetch_headers["status"] == call["response"]["status"], "observer response status differs")
        require(stamp(first) <= stamp(created) <= stamp(sent) <= stamp(response) <= stamp(body) and
                stamp(response) <= stamp(fetch_headers) <= stamp(body_start) <= stamp(body_end) <= stamp(last) and
                body["sequence"] < body_end["sequence"] and stamp(body) <= stamp(body_end), "observer request/body order changed")
        # http_proof already binds the complete original bytes/status to the
        # relay. An informational socket event cannot supply a missing reply.
        require(stamp(call["request"]) <= stamp(first) and
                stamp(body_end) <= stamp(call["response"]) <= stamp(last), "observer differs from complete original Fetch ledger")
        equal({key: last[key] for key in ("outcome", "stage", "observation_status", "request_identity", "connection_identity", "request_ids", "connection_ids")},
              {"outcome": "response", "stage": "evidence", "observation_status": "RECORDED", "request_identity": "OBSERVED",
               "connection_identity": "OBSERVED", "request_ids": [request_id], "connection_ids": [sent["connection_id"]]}, "observer terminal lost original identities/completeness")
        connection = sent["connection_id"]
        require(connection not in bound, "transport connection shared by multiple original requests")
        bound[connection] = {"sent": sent, "body": body}
    require(set(connections) == set(bound), "unbound transport connection observation")
    closed = informational = 0
    for connection, records in connections.items():
        observed = only([row for row in records if row["event"] == "socket_observed"], "transport socket identity count")
        kinds = Counter(row["event"] for row in records)
        require(records[0] is observed and set(kinds) <= {"socket_observed", "socket_end", "socket_error", "socket_close"} and
                all(count == 1 for count in kinds.values()), "repeated socket lifecycle event")
        sent, body = bound[connection]["sent"], bound[connection]["body"]
        require(observed["sequence"] < sent["sequence"] and stamp(observed) <= stamp(sent), "socket observed after original request binding")
        for row in records:
            extra = {"had_error"} if row["event"] == "socket_close" else (
                {"error_name", "error_code", "cause_code"} if row["event"] == "socket_error" else set())
            equal(set(row), {"schema", "phase", "sequence", "monotonic_ns", "event", "connection_id"} | extra,
                  "socket observation fields changed")
        error = next((row for row in records if row["event"] == "socket_error"), None)
        close = next((row for row in records if row["event"] == "socket_close"), None)
        if error is not None:
            # Pinned Node22.16.0 emits UND_ERR_INFO when disposing an H1 socket
            # after onComplete. The observer records only safe codes, not the
            # literal reason. Require the same connection's unique completed
            # original response; a code whitelist by itself is insufficient.
            equal({key: error[key] for key in ("error_name", "error_code", "cause_code")},
                  {"error_name": "UNKNOWN", "error_code": "UND_ERR_INFO", "cause_code": "UNKNOWN"},
                  "socket error is not the pinned informational disposal")
            require(body["sequence"] < error["sequence"] and stamp(body) <= stamp(error),
                    "informational disposal preceded its original request body completion")
            informational += 1
        for row in records[1:]:
            require(sent["sequence"] < row["sequence"] and stamp(sent) <= stamp(row),
                    "socket event preceded original request binding")
        if close is not None:
            require(records[-1] is close and sent["sequence"] < close["sequence"], "socket event after close or close before original binding")
            require(close["had_error"] is (error is not None), "socket close error flag lacks its exact informational observation")
            if error is not None:
                require(error["sequence"] < close["sequence"] and stamp(error) <= stamp(close), "socket closed before informational disposal")
            closed += 1
    # This recorder deliberately stops before claiming every socket's full
    # lifetime. Unobserved close is allowed, including after complete INFO, but
    # the remaining identities must exactly match its recorded open set.
    equal(trace[-1]["remaining_connections"], len(connections) - closed, "observer remaining connection inventory differs")
    return {"calls": len(calls), "original_request_identities": len(calls), "connections": len(connections),
            "informational_disposals": informational, "observed_closed_connections": closed,
            "remaining_connections": len(connections) - closed, "observation_status": "RECORDED"}


def normalized(item, field):
    """Adapt complete new bytes to the existing independent version solver."""
    row = dict(item[field])
    row["request_bytes"] = row["request_body_bytes"]
    row["request_sha256"] = row["request_body_sha256"]
    if row["path"].endswith("/head"):
        row["head_request_bytes"] = list(raw_bytes(row, "request_body"))
    if field == "response":
        row["response_bytes"] = row["response_body_bytes"]
        row["response_sha256"] = row["response_body_sha256"]
        if row["path"].endswith("/head"):
            row["head_response_bytes"] = list(raw_bytes(row, "response_body"))
    return row


def normal_versions(exchanges):
    # Only this one declared F corruption/restoration is outside HEAD6 history.
    # Its S-only seed history remains ordinary and is independently included.
    selected = [item for item in exchanges if item["request"]["path"] != head_path("known_quarantine") or item["request"]["worker"] == "S"]
    requests = {item["request"]["request_serial"]: normalized(item, "request") for item in selected}
    responses = {item["request"]["request_serial"]: normalized(item, "response") for item in selected}
    value = WIRE.object_versions(requests, responses)
    require(value["http_interval_binding"] == "NOT_REQUESTED", "forbidden timestamp-based RPC attribution")
    return value


def native_policy(policy):
    return [{**item, "principal": int(item["principal"])} for item in policy]


def advance(before, nonce, **fields):
    value = deepcopy(before)
    value.update(revision=before["revision"] + 1, head_serial=before["head_serial"] + 1,
                 transition={"revision": before["revision"] + 1, "nonce": nonce})
    value.update(fields)
    return value


def head_history(exchanges, calls):
    accepted, objects = defaultdict(dict), {}
    object_puts, object_reads = defaultdict(list), defaultdict(list)
    for item in exchanges:
        request, response = item["request"], item["response"]
        path = request["path"]
        if "/objects/" in path:
            if request["method"] == "PUT":
                original = raw_bytes(request, "request_body")
                frame(original, path)
                require(request["if_none_match"] == "*" and request["if_match"] is None, "immutable was overwritten")
                if response["status"] == 200:
                    require(path not in objects, "immutable accepted twice")
                    objects[path] = original
                    object_puts[path].append(item)
            elif response["status"] == 200:
                original = raw_bytes(response, "response_body")
                frame(original, path)
                object_reads[path].append(item)
            continue
        if request["worker"] == "F" or request["method"] != "PUT" or response["status"] != 200:
            continue
        name = next(name for name in NAMES if path == head_path(name))
        value = head(raw_bytes(request, "request_body"), name)
        require(value["revision"] not in accepted[name], "duplicate accepted business revision")
        accepted[name][value["revision"]] = {"head": value, "etag": response["etag"], "exchange": item,
                                             **pack(raw_bytes(request, "request_body"))}
    require(sum(len(values) for values in accepted.values()) == 28, "normal accepted HEAD denominator changed")
    for path, values in object_reads.items():
        require(path in objects, "successful immutable GET omitted original conditional create")
        for item in values:
            equal(raw_bytes(item["response"], "response_body"), objects[path], "immutable GET bytes changed after create")
    bases, selected_closures = {}, {}
    for index, name in enumerate(NAMES):
        values = accepted[name]
        expected_revisions = list(range(1, 7 if name == "success" else 6 if name in ("put_unknown", "stale_412") else 5))
        equal(sorted(values), expected_revisions, "Scope publication history differs from fixed program")
        initial, active, written, base = [values[number]["head"] for number in (1, 2, 3, 4)]
        expected_initial = {"format": 6, "scope": {key: int(value) for key, value in SCOPES[name].items()},
                            "head_serial": 1, "storage": {"active_generation": 1, "allocated_through": 1, "plan": None, "sweep": None},
                            "revision": 1, "transition": {"revision": 1, "nonce": 10000 + index * 10},
                            "sequence": 0, "owner_epoch": 1, "owner_instance": 8101, "active": False, "auth_epoch": 1,
                            "policy": [{"principal": 11, "read": True, "write": True, "admin": True}],
                            "lifecycle": "ready", "creation": None, "deletion": None, "data_root": initial["data_root"],
                            "quota": {"max_bytes": 10737418240}, "retention": {"max_entries": 4096, "max_result_bytes": 268435456},
                            "request_epoch": 1, "windows": [{"epoch": 1, "root": initial["windows"][0]["root"], "count": 0, "result_bytes": 0}]}
        equal(initial, expected_initial, "seed initial authority/default quota/retention changed")
        equal(active, advance(initial, 10001 + index * 10, active=True), "activation changed unrelated HEAD fields")
        raw_result, _ = WIRE.committed(calls["s_" + name + "_execute"]["envelope"]["value"])
        receipt = calls["s_" + name + "_execute"]["envelope"]["value"]["receipt"]
        expected_written = advance(active, 1, sequence=1, data_root=receipt["data_root"],
                                   windows=[{"epoch": 1, "root": written["windows"][0]["root"], "count": 1, "result_bytes": len(raw_result)}])
        equal(written, expected_written, "SQL authority differs from original receipt/index bytes")
        equal(base, advance(written, 10002 + index * 10, auth_epoch=2, policy=native_policy(BASE_POLICY)), "seed policy changed unrelated data/owner state")
        for revision, operation in ((1, "create"), (2, "activate"), (4, "policy")):
            equal(calls["s_" + name + "_" + operation]["envelope"]["value"], status_from_head(values[revision]["head"]),
                  "seed administrative ACK differs from actual accepted HEAD")
        for revision, operation in ((1, "create"), (2, "activate"), (3, "execute"), (4, "policy")):
            require(stamp(values[revision]["exchange"]["response"]) < stamp(calls["s_" + name + "_" + operation]["response"]),
                    "seed ACK preceded original durable authority response")
        bases[name] = values[4]
        selected = seed_dependencies(name, initial, written, receipt, raw_result, objects)
        selected_closures[name] = sorted(selected)
        # Full fixed seed closure was persisted and read back before SQL HEAD.
        publication = stamp(values[3]["exchange"]["request"])
        for path in selected:
            require(any(stamp(item["response"]) < publication for item in object_puts[path]), "seed dependency creation followed SQL publication")
            require(any(stamp(item["response"]) < publication for item in object_reads[path]), "seed dependency lacks original durable readback")
    success5 = advance(bases["success"]["head"], 20001, owner_epoch=2, owner_instance=8202, active=False)
    success6 = advance(success5, 20002, auth_epoch=3, policy=native_policy(NEXT_POLICY))
    equal(accepted["success"][5]["head"], success5, "takeover did not preserve exact original data/ACL")
    equal(accepted["success"][6]["head"], success6, "metadata policy changed unrelated authority fields")
    equal(accepted["put_unknown"][5]["head"], advance(bases["put_unknown"]["head"], 22001, auth_epoch=3, policy=native_policy(NEXT_POLICY)),
          "unknown accepted candidate changed original policy delta")
    equal(accepted["stale_412"][5]["head"], advance(bases["stale_412"]["head"], 23002, auth_epoch=3, policy=native_policy(NEXT_POLICY)),
          "competitor changed unrelated authority fields")
    expected_statuses = {"m_success_status_before": bases["success"], "m_success_takeover": accepted["success"][5],
                         "m_success_policy": accepted["success"][6], "m_success_status_after": accepted["success"][6],
                         "o_get_unknown_status": bases["get_unknown"], "o_put_unknown_status": accepted["put_unknown"][5],
                         "o_stale_policy": accepted["stale_412"][5], "o_permission_status": bases["permission"],
                         "m_quarantine_repaired_status": bases["known_quarantine"]}
    for command, value in expected_statuses.items():
        equal(calls[command]["envelope"]["value"], status_from_head(value["head"]), "fresh administrative observation differs from actual HEAD")
        require(stamp(value["exchange"]["response"]) < stamp(calls[command]["response"]), "metadata ACK preceded its authority effect")
    return accepted, bases, objects, selected_closures


def seed_dependencies(name, initial, written, receipt, raw_result, objects):
    """Complete SMALL fixed seed graph, not a general native integrity checker."""
    selected = set()
    def load(digest, kind):
        path = object_prefix(name) + WIRE.sha256_text(digest)
        require(path in objects, "fixed seed dependency missing")
        selected.add(path)
        payload, raw = frame(objects[path], path)
        require(payload["kind"] == kind, "fixed seed typed edge changed")
        return payload["value"], raw
    manifest, raw = load(initial["data_root"], "manifest")
    require(raw == b"", "initial manifest had external raw bytes")
    equal(manifest, {"page_count": 0, "root": None}, "initial manifest is not empty")
    index, raw = load(initial["windows"][0]["root"], "index")
    require(raw == b"", "initial index had external raw bytes")
    equal(index, {"kind": "leaf", "epoch": 1, "entries": []}, "initial request index is not empty")
    manifest, raw = load(written["data_root"], "manifest")
    require(raw == b"" and set(manifest) == {"page_count", "root"} and type(manifest["page_count"]) is int and
            1 <= manifest["page_count"] <= 32, "fixed seed data image geometry changed")
    node, raw = load(manifest["root"], "node")
    require(raw == b"" and set(node) == {"level", "first_chunk", "children"} and node["level"] == node["first_chunk"] == 0 and
            type(node["children"]) is list and len(node["children"]) == 1, "fixed seed node geometry changed")
    chunk, raw = load(node["children"][0], "chunk")
    equal(chunk, {"first_page": 1, "bytes": []}, "fixed seed chunk metadata changed")
    require(len(raw) == manifest["page_count"] * 4096 and raw[:18] == b"SQLite format 3\0\x10\0", "fixed seed complete SQLite image bytes changed")
    index, raw = load(written["windows"][0]["root"], "index")
    require(raw == b"", "retained index had external raw bytes")
    native_request = {key: int(value) if key != "fingerprint" else value for key, value in receipt["request"].items()}
    equal(index, {"kind": "leaf", "epoch": 1, "entries": [{"request": native_request,
          "outcome": {"state": "committed", "result": receipt["result_hash"]}, "result_bytes": len(raw_result)}]}, "fixed seed index request/result identity changed")
    result, raw = load(receipt["result_hash"], "result")
    equal(result, {"request": native_request, "sequence": 1, "transition": {"revision": 3, "nonce": 1},
                   "data_root": written["data_root"], "bytes": []}, "retained Result semantic identity changed")
    equal(raw, raw_result, "retained original result bytes differ from ACK")
    return selected


def metadata_projection(exchanges, calls, bases, accepted, config, process):
    stream = [projected_exchange(item) for item in exchanges if item["request"]["worker"] == "M"]
    projected_calls = []
    for spec in COMMANDS:
        if spec["worker"] != "M":
            continue
        call = calls[spec["id"]]
        outcome = call["operation"]["finish"]
        projected_calls.append({"command": spec["id"], "request_body": parse(call["body"]), "status": call["response"]["status"],
            "credential_sha256": call["relay"]["request"]["credential_sha256"],
            "outcome": {key: deepcopy(outcome[key]) for key in ("ok", "value" if outcome["ok"] else "error")},
            "source": {"ledger": "http-client-ledger.jsonl", "call_id": call["request"]["call_id"],
                       "request_body_sha256": sha(call["body"]), "response_body_sha256": sha(call["response_body"]),
                       "http_file": "http-proxy.jsonl", "http_serial": call["relay"]["request"]["http_serial"],
                       "handler_id": call["relay"]["request"]["handler_id"],
                       "http_sequences": [call["relay"][key]["sequence"] for key in ("request", "forwarded", "response", "terminal")],
                       "node_file": "metadata-node.jsonl", "node_sequences": [call["operation"][key]["sequence"] for key in ("start", "authorization", "finish")]}})
    projection = {"schema": 1, "calls": projected_calls, "stream": stream, "credentials": config["credential_sha256"],
                  "bases": {name: {"etag": value["etag"], **pack(raw_bytes(value, "body")),
                             "source": projected_exchange(value["exchange"])["source"]} for name, value in bases.items()},
                  "success_takeover": {"etag": accepted["success"][5]["etag"], **pack(raw_bytes(accepted["success"][5], "body")),
                                        "source": projected_exchange(accepted["success"][5]["exchange"])["source"]},
                  "competitor": projected_exchange(accepted["stale_412"][5]["exchange"]),
                  "last_http_response_ns": max(stamp(call["response"]) for name, call in calls.items() if BY_ID[name]["worker"] == "M"),
                  "lifetime": process["M_lifetime"],
                  "immutable_samples": [projected_exchange(item) for item in exchanges if "/objects/" in item["request"]["path"] and
                                        item["response"]["status"] == 200 and item["request"]["method"] in ("GET", "PUT")]}
    metadata_semantics(projection)
    # Check all original M exact reads and the four immutable candidate bodies.
    expected_reads = [("success", bases["success"]), ("success", bases["success"]), ("success", accepted["success"][5]),
                      ("success", accepted["success"][6]), ("get_unknown", bases["get_unknown"]), ("put_unknown", bases["put_unknown"]),
                      ("stale_412", bases["stale_412"]), ("permission", bases["permission"]), ("permission", bases["permission"])]
    gets = [item for item in stream if item["request"]["method"] == "GET"]
    for item, (name, expected) in zip(gets[:9], expected_reads):
        equal([item["request"]["path"], item["response"]["etag"]], [head_path(name), expected["etag"]], "M exact GET binds another original authority")
        equal(raw_bytes(item["response"], "response_body"), raw_bytes(expected), "M exact HEAD body/ETag pair differs")
    expected_puts = [("success", 20001, accepted["success"][5]["head"]), ("success", 20002, accepted["success"][6]["head"]),
                     ("put_unknown", 22001, accepted["put_unknown"][5]["head"]),
                     ("stale_412", 23001, advance(bases["stale_412"]["head"], 23001, owner_epoch=2, owner_instance=8202, active=False))]
    previous = None
    put_index = 0
    for item in stream:
        if item["request"]["method"] == "GET":
            previous = item
            continue
        name, nonce, expected = expected_puts[put_index]
        put_index += 1
        equal(head(raw_bytes(item["request"], "request_body"), name), expected, "M original candidate changed allowed delta/nonce")
        require(previous is not None and previous["request"]["path"] == item["request"]["path"] and
                previous["response"]["etag"] == item["request"]["if_match"] and
                stamp(previous["response"]) < stamp(item["request"]), "M candidate did not retain its own preceding exact GET condition")
    return projection


def fault_and_repair_proof(directory, events, exchanges, calls, bases, accepted):
    groups = defaultdict(list)
    for row in events:
        groups[row["event"]].append(row)
    faults = {
        "drop_get_unknown": {"worker": "M", "method": "GET", "path": head_path("get_unknown"), "stage": "after_backend_response", "kind": "drop"},
        "drop_put_unknown": {"worker": "M", "method": "PUT", "path": head_path("put_unknown"), "nonce": "22001", "stage": "after_backend_response", "kind": "drop"},
        "hold_stale_put": {"worker": "M", "method": "PUT", "path": head_path("stale_412"), "nonce": "23001", "stage": "before_forward", "kind": "hold"}}
    require(Counter(row["id"] for row in groups["fault_armed"]) == Counter(faults.keys()) and
            Counter(row["id"] for row in groups["fault_entered"]) == Counter(faults.keys()), "fault arm/enter denominator changed")
    equal([row["id"] for row in groups["fault_released"]], ["hold_stale_put"], "unplanned manual fault release")
    by_serial = {item["request"]["request_serial"]: item for item in exchanges}
    suppression = {item["terminal"]["fault_id"]: item for item in exchanges if item["terminal"]["event"] == "object_response_suppressed"}
    equal(set(suppression), {"drop_get_unknown", "drop_put_unknown"}, "unaccounted/missing actual response loss")
    require(sum(item["terminal"]["event"] == "object_response_suppressed" for item in exchanges) == 2, "response-loss attempt repeated")
    for name, expected in faults.items():
        arm = only([row for row in groups["fault_armed"] if row["id"] == name], "fault arm count")
        enter = only([row for row in groups["fault_entered"] if row["id"] == name], "fault entry count")
        equal({key: arm[key] for key in expected}, expected, "fault predicate changed")
        require(enter["request_serial"] in by_serial, "fault refers to missing original S3 attempt")
        item = by_serial[enter["request_serial"]]
        for key in ("worker", "method", "path"):
            equal(item["request"][key], expected[key], "fault hit another authority attempt")
        if "nonce" in expected:
            require(str(parse(raw_bytes(item["request"], "request_body"))["transition"]["nonce"]) == expected["nonce"], "fault hit another original nonce")
        require(stamp(arm) < stamp(item["request"]) <= stamp(enter), "fault was not armed before original attempt")
        if expected["kind"] == "drop":
            require(item is suppression[name] and item["response"]["status"] == 200 and
                    stamp(item["response"]) <= stamp(enter) <= stamp(item["terminal"]), "loss lacks actual successful backend response")
            command = "m_get_unknown_takeover" if name == "drop_get_unknown" else "m_put_unknown_policy"
            require(stamp(item["terminal"]) < stamp(calls[command]["response"]), "UNKNOWN preceded explicit original response loss")
            observer = "o_get_unknown_status" if name == "drop_get_unknown" else "o_put_unknown_status"
            require(stamp(calls[command]["operation"]["finish"]) < stamp(calls[observer]["request"]), "observer was not fresh after original UNKNOWN")
        else:
            release = only(groups["fault_released"], "stale release count")
            require(release["request_serial"] == enter["request_serial"] and
                    stamp(enter) < stamp(calls["o_stale_policy"]["request"]) < stamp(calls["o_stale_policy"]["response"]) < stamp(release) < stamp(item["forwarded"]) and
                    stamp(release) - stamp(enter) <= 10 * 10**9 and item["response"]["status"] == 412,
                    "original stale CAS was not held behind the accepted competitor")
            require(item["request"]["if_match"] == bases["stale_412"]["etag"] and
                    accepted["stale_412"][5]["exchange"]["request"]["if_match"] == bases["stale_412"]["etag"],
                    "race did not consume one original same-ETag candidate pair")
    maintenance = [item for item in exchanges if item["request"]["worker"] == "F"]
    equal([(item["request"]["method"], item["request"]["path"], item["response"]["status"]) for item in maintenance],
          [("GET", head_path("known_quarantine"), 200), ("PUT", head_path("known_quarantine"), 200),
           ("PUT", head_path("known_quarantine"), 200)], "maintenance request denominator changed")
    original, corrupt, restore = maintenance
    seed = bases["known_quarantine"]
    equal(raw_bytes(original["response"], "response_body"), raw_bytes(seed), "maintenance GET did not capture the original complete HEAD")
    require(original["response"]["etag"] == seed["etag"], "maintenance GET body and ETag were not one original version")
    equal(raw_bytes(corrupt["request"], "request_body"), b"{}", "unplanned authority corruption bytes")
    require(corrupt["request"]["if_match"] == original["response"]["etag"] and corrupt["request"]["if_none_match"] is None and
            restore["request"]["if_match"] == corrupt["response"]["etag"] and restore["request"]["if_none_match"] is None,
            "maintenance did not retain exact original conditional ETags")
    equal(raw_bytes(restore["request"], "request_body"), raw_bytes(original["response"], "response_body"), "maintenance re-encoded/reconstructed the original HEAD")
    # Deliberate exact restore may repeat a body-derived ETag. This exception is
    # isolated to this key and these three declared signed requests only.
    require(stamp(calls["m_permission_policy"]["operation"]["finish"]) < stamp(original["request"]) and
            stamp(original["response"]) < stamp(corrupt["request"]) < stamp(corrupt["response"]) < stamp(calls["m_quarantine_bad_status"]["request"]) and
            stamp(calls["m_quarantine_bad_status"]["operation"]["finish"]) < stamp(restore["request"]) < stamp(restore["response"]) < stamp(calls["m_quarantine_repaired_status"]["request"]),
            "bad/restore sequence did not bracket the original resident handle observations")
    q_gets = [item for item in exchanges if item["request"]["worker"] == "M" and item["request"]["path"] == head_path("known_quarantine")]
    require(len(q_gets) == 4 and all(item["request"]["method"] == "GET" for item in q_gets), "quarantine control sequence changed")
    for index, item in enumerate(q_gets):
        expected_raw = b"{}" if index == 0 else raw_bytes(seed)
        expected_etag = corrupt["response"]["etag"] if index == 0 else restore["response"]["etag"]
        equal(raw_bytes(item["response"], "response_body"), expected_raw, "quarantine read body changed")
        require(item["response"]["etag"] == expected_etag, "quarantine read lost exact body/ETag binding")
    for index, (name, item) in enumerate(zip(MAINTENANCE, maintenance)):
        start = only([row for row in groups["fixture_started"] if row["id"] == name], "maintenance offered count")
        stop = only([row for row in groups["fixture_process_stopped"] if row["id"] == name], "maintenance completed count")
        equal([start["method"], start["path"], start["if_match"]], [item["request"][key] for key in ("method", "path", "if_match")], "signed maintenance inputs changed")
        equal(raw_bytes(start), raw_bytes(item["request"], "request_body"), "maintenance sent another payload")
        require(start["source_read_serial"] == (None if index == 0 else original["request"]["request_serial"]), "maintenance rebound source read")
        require(stamp(start) < stamp(item["request"]) < stamp(item["response"]) < stamp(stop), "maintenance process/request ordering changed")
        require(stop["status"] == item["response"]["status"] and stop["etag"] == item["response"]["etag"], "curl outcome differs from backend")
        raw = raw_bytes(stop)
        equal(raw, raw_bytes(item["response"], "response_body"), "curl did not receive exact backend bytes")
        equal((Path(directory) / (name + ".body")).read_bytes(), raw, "curl original body file differs")
        for suffix in ("headers", "stdout", "stderr"):
            require(sha((Path(directory) / (name + "." + suffix)).read_bytes()) == stop[suffix + "_sha256"], "curl original output file digest differs")
        require((Path(directory) / (name + ".stdout")).read_bytes() == b"200" and (Path(directory) / (name + ".stderr")).read_bytes() == b"",
                "curl original status output/errors differ")
        headers = (Path(directory) / (name + ".headers")).read_bytes().decode("iso-8859-1")
        blocks = [part for part in re.split(r"\r?\n\r?\n", headers) if part.strip()]
        last = blocks[-1].splitlines()
        require(re.fullmatch(r"HTTP/[0-9.]+ 200(?: .*)?", last[0]) is not None, "curl final original status header changed")
        etags = [line.split(":", 1)[1].strip() for line in last[1:] if line.lower().startswith("etag:")]
        equal(etags, [stop["etag"]], "curl raw header ETag differs from exact backend response")
    require(Counter(row["id"] for row in groups["fixture_started"]) == Counter(MAINTENANCE), "unplanned maintenance input")
    return {"declared_faults": 3, "actual_response_losses": 2, "same_original_etag_conflict": 1,
            "signed_maintenance_requests": 3, "restored_bytes": "exact original GET bytes", "quarantine_sequence": "same resident control Engine"}


def identity(value):
    require(value.get("pid_source") == "owned_Popen_child" and type(value.get("pid")) is int and value["pid"] > 0 and
            type(value.get("spawn_monotonic_ns")) is int and value["spawn_monotonic_ns"] > 0, "missing actual owned child identity")
    return {key: value[key] for key in ("pid", "spawn_monotonic_ns", "pid_source")}


def wait4(value, expected):
    require(type(value["wait_status"]) is int and value["wait_status"] == expected, "original owned child exit status differs")
    usage = value["kernel_usage"]
    require(usage["available"] is True and usage["source"] == "kernel_wait4_owned_child" and type(usage["maxrss_bytes"]) is int and
            usage["maxrss_bytes"] > 0 and all(type(usage[key]) in (int, float) and usage[key] >= 0 for key in ("user_seconds", "system_seconds")),
            "missing original kernel wait4/usage")


EVENTS = {"private_created", "backend_started", "backend_unsigned_probe", "proxy_listener_started", "service_started", "service_ready",
          "node_started", "node_event", "operator_command", "fault_armed", "fault_entered", "fault_released", "fixture_started",
          "fixture_process_started", "fixture_process_stopped", "cache_observed", "node_stop_requested", "node_stopped",
          "service_stop_requested", "service_stopped", "proxy_listener_stopped", "backend_stop_requested", "backend_stopped",
          "cleanup_finished", "private_remove_started", "private_remove_finished"}


def process_proof(directory, events, node, calls, http_handlers, s3_handlers, config, configs, build):
    directory = Path(directory)
    require(all(row["event"] in EVENTS for row in events), "failure/forced cleanup/unplanned lifecycle event")
    groups = defaultdict(list)
    for row in events:
        groups[row["event"]].append(row)
    created = only(groups["private_created"], "private runtime creation count")
    equal({key: created[key] for key in ("path", "device", "inode")}, config["private"], "private runtime configuration identity differs")
    require(events[0] is created, "private runtime was not recorded before use")
    tools = parse((directory / "metadata-tools.json").read_bytes())
    require(set(tools) == {"node", "weed", "curl"}, "tool inventory changed")
    for value in tools.values():
        require(set(value) == {"path", "sha256", "version"} and Path(value["path"]).is_absolute() and
                type(value["version"]) is str and value["version"], "tool provenance incomplete")
        WIRE.sha256_text(value["sha256"])
        if Path(value["path"]).exists():
            require(BUILD.file_digest(Path(value["path"])) == value["sha256"], "actual tool bytes changed")
    require(tools["node"]["version"] == "v22.16.0" and tools["weed"]["sha256"] ==
            "eb9adf3a75b53c32f5ad9ba856e1fb652dae03dc6f6222673c3f88c0cbd25d0e" and
            "4.51 153ab668c99731a6d29492bf6c61d0b4fa701101" in tools["weed"]["version"], "unpinned actual tool runtime")
    owned = BUILD.OwnedChildren()
    backend_start = only(groups["backend_started"], "backend start count")
    backend_request = only(groups["backend_stop_requested"], "backend shutdown request count")
    backend_stop = only(groups["backend_stopped"], "backend wait4 count")
    require(backend_start["access_key_sha256"] == config["backend"]["access_key_sha256"], "backend credential identity differs")
    equal(backend_start["binary"], {key: tools["weed"][key] for key in ("path", "sha256")}, "backend binary binding changed")
    require(backend_request["signal"] == "SIGKILL" and backend_request["reason"] == "planned_fixture_shutdown", "backend termination was not planned fixture cleanup")
    before, after = backend_start["processes"], backend_stop["processes"]
    require(len(before) == len(after) == 4 and len({row["role"] for row in before}) == 4, "backend owned process denominator changed")
    equal(backend_request["processes"], before, "backend stop targeted different original children")
    for child in before:
        stopped = only([row for row in after if row["role"] == child["role"]], "backend role wait4 count")
        equal(identity(child), identity(stopped), "backend child incarnation changed")
        wait4(stopped, -9)
        require(identity(child)["spawn_monotonic_ns"] <= stamp(backend_start) < stamp(backend_request) < stamp(backend_stop), "backend lifecycle order changed")
        owned.register(identity(child), stamp(backend_stop))
    unsigned = only(groups["backend_unsigned_probe"], "backend unsigned authentication check count")
    require(unsigned["endpoint"] == config["backend"]["endpoint"] and unsigned["method"] == "GET" and
            unsigned["path"] == "/scap-test/fixture-ready" and unsigned["authorization"] is None and unsigned["status"] == 403 and
            raw_bytes(unsigned, "request_body") == b"", "unsigned backend admission unexpectedly succeeded")
    raw_bytes(unsigned, "response_body")
    require(stamp(backend_start) < stamp(unsigned), "backend security check preceded owned backend")
    node_start = only(groups["node_started"], "Node start count")
    node_request = only(groups["node_stop_requested"], "Node graceful-stop count")
    node_stop = only(groups["node_stopped"], "Node wait4 count")
    equal(identity(node_start["identity"]), identity(node_request["identity"]), "Node stop targets another child")
    equal(identity(node_start["identity"]), identity(node_stop["identity"]), "Node wait4 belongs to another child")
    equal(node_start["binary"], {key: tools["node"][key] for key in ("path", "sha256")}, "Node binary changed")
    require(node_start["identity"]["pid"] == node[0]["self_pid"] and node[0]["version"] == tools["node"]["version"], "Node self identity differs from owned child")
    WIRE.sha256_text(node_start["configuration_sha256"])
    require(type(node_start["spawn_requested_ns"]) is int and node_start["spawn_requested_ns"] < node_start["identity"]["spawn_monotonic_ns"] <= stamp(node_start) and
            node_start["spawn_requested_ns"] < stamp(node[0]) and stamp(node_start) < stamp(node_request) < stamp(node[-1]) < stamp(node_stop) and
            node_request["forced"] is False and node_stop["forced"] is False and node_stop["termination_error"] is None, "Node forced/incomplete termination")
    wait4(node_stop, 0)
    owned.register(identity(node_start["identity"]), stamp(node_stop))
    require(node_stop["stderr_sha256"] == sha((directory / "node.stderr.log").read_bytes()) and
            node_stop["ledger_sha256"] == sha((directory / "metadata-node.jsonl").read_bytes()), "Node original output ledger changed")
    services = {}
    require(len(groups["service_started"]) == len(groups["service_ready"]) == len(groups["service_stop_requested"]) == len(groups["service_stopped"]) == 2,
            "service restart/extra process hidden")
    for worker in ("S", "M"):
        start = only([row for row in groups["service_started"] if row["worker"] == worker], "service start identity count")
        ready = only([row for row in groups["service_ready"] if row["worker"] == worker], "service ready identity count")
        requested = only([row for row in groups["service_stop_requested"] if row["worker"] == worker], "service stop identity count")
        stop = only([row for row in groups["service_stopped"] if row["worker"] == worker], "service wait4 identity count")
        for row in (ready, requested, stop):
            equal(identity(row["identity"]), identity(start["identity"]), "service control Engine process incarnation changed")
        equal(start["binary"], build["binary"], "actual daemon differs from source-bound release")
        for key in ("configuration_file", "cache_directory", "backend_endpoint"):
            equal(start[key], config["services"][worker][key], "daemon started with another original configuration")
        require(start["configuration_sha256"] == configs[worker]["sha256"] and type(start["spawn_requested_ns"]) is int and
                start["spawn_requested_ns"] < start["identity"]["spawn_monotonic_ns"] <= stamp(start) < stamp(ready), "daemon spawn/configuration receipt changed")
        require(ready["status"] == 200, "daemon readiness failed")
        equal(parse(raw_bytes(ready)), {"status": "alive", "protocol": 1}, "liveness response changed")
        chosen = [call for name, call in calls.items() if BY_ID[name]["worker"] == worker]
        require(stamp(ready) < min(stamp(call["request"]) for call in chosen) and
                max(stamp(call["operation"]["finish"]) for call in chosen) < stamp(node_stop) < stamp(requested) < stamp(stop) and
                requested["signal"] == "SIGINT" and stop["termination_error"] is None, "service work/owned shutdown ordering changed")
        wait4(stop, 0)
        owned.register(identity(start["identity"]), stamp(stop))
        require(stop["stdout_sha256"] == sha((directory / ("service-" + worker + ".log")).read_bytes()), "daemon original log changed")
        services[worker] = {"start": start, "ready": ready, "stop": stop}
    require(max(stamp(calls["s_" + name + "_policy"]["operation"]["finish"]) for name in NAMES) < stamp(services["M"]["start"]),
            "M existed before the six seed histories completed")
    require(len(groups["fixture_process_started"]) == len(groups["fixture_process_stopped"]) == 3, "maintenance child inventory changed")
    for name in MAINTENANCE:
        start = only([row for row in groups["fixture_process_started"] if row["id"] == name], "maintenance child start count")
        stop = only([row for row in groups["fixture_process_stopped"] if row["id"] == name], "maintenance child wait4 count")
        equal(identity(start["identity"]), identity(stop["identity"]), "maintenance child incarnation changed")
        equal(start["binary"], {key: tools["curl"][key] for key in ("path", "sha256")}, "maintenance tool binary changed")
        require(type(start["spawn_requested_ns"]) is int and start["spawn_requested_ns"] < start["identity"]["spawn_monotonic_ns"] <= stamp(start) < stamp(stop) < stamp(node_stop),
                "maintenance child escaped original workload lifetime")
        wait4(stop, 0)
        owned.register(identity(start["identity"]), stamp(stop))
    caches = groups["cache_observed"]
    equal([row["label"] for row in caches], ["before_metadata", "after_metadata"], "compute-cache observation inventory changed")
    for row in caches:
        require(row["worker"] == "M" and row["path"] == config["services"]["M"]["cache_directory"] and row["files"] == [], "metadata worker created SQLite/WAL/other compute files")
        seen = set()
        for item in row["directories"]:
            path = PurePosixPath(item["path"])
            require(set(item) == {"path", "device", "inode"} and not path.is_absolute() and path.as_posix() == item["path"] and
                    ".." not in path.parts and item["path"] != "." and item["path"] not in seen and
                    all(type(item[key]) is int and item[key] > 0 for key in ("device", "inode")), "cache directory identity changed")
            seen.add(item["path"])
    require(stamp(services["M"]["ready"]) <= stamp(caches[0]) < stamp(calls["m_success_status_before"]["request"]) and
            stamp(calls["m_quarantine_policy"]["operation"]["finish"]) < stamp(caches[1]) < stamp(services["M"]["stop"]), "cache observations did not surround M workload")
    starts, stops = groups["proxy_listener_started"], groups["proxy_listener_stopped"]
    equal(Counter(row["listener_id"] for row in starts), Counter(LISTENERS.keys()), "proxy listener start denominator changed")
    equal(Counter(row["listener_id"] for row in stops), Counter(LISTENERS.keys()), "proxy listener stop denominator changed")
    all_handlers = {**http_handlers, **s3_handlers}
    m_close = None
    for listener, (channel, worker) in LISTENERS.items():
        start = only([row for row in starts if row["listener_id"] == listener], "listener start count")
        stop = only([row for row in stops if row["listener_id"] == listener], "listener stop count")
        expected_endpoint = config["s3_endpoints"][worker] if channel == "s3" else config["endpoints"][worker].removesuffix("/v1")
        equal([start["channel"], start["worker"], start["endpoint"]], [channel, worker, expected_endpoint], "listener bound wrong interface")
        equal([stop["channel"], stop["worker"]], [channel, worker], "listener shutdown identity changed")
        selected = [records for key, records in all_handlers.items() if key.startswith(listener + ":")]
        require(type(stop["accepted_handlers"]) is int and type(stop["finished_handlers"]) is int and
                stop["accepted_handlers"] == stop["finished_handlers"] == len(selected) and type(stop["active_handlers"]) is int and
                stop["active_handlers"] == 0 and stop["serve_thread_joined"] is True and stop["handlers_joined"] is True,
                "proxy lifetime tail is not completely joined")
        require(max(stamp(value["stop"]) for value in services.values()) < stamp(stop) < stamp(backend_request), "proxy closed before daemon exit or after backend shutdown")
        for records in selected:
            require(stamp(start) < min(stamp(row) for row in records) <= max(stamp(row) for row in records) < stamp(stop), "recorded handler escaped full listener lifetime")
        if listener == "s3-M":
            m_close = stop
    cleanup = only(groups["cleanup_finished"], "cleanup completion count")
    remove = only(groups["private_remove_started"], "private removal count")
    gone = only(groups["private_remove_finished"], "private absence observation count")
    require(cleanup["errors"] == [] and stamp(backend_stop) < stamp(cleanup) < stamp(remove) < stamp(gone) and events[-1] is gone,
            "runtime removed before complete wait4/join or cleanup had errors")
    for row in (remove, gone):
        equal({key: row[key] for key in ("path", "device", "inode")}, config["private"], "cleanup removed another private runtime")
    require(gone["observed_absence"] is True and len(owned.incarnations) == 10, "original runtime absence/owned child denominator incomplete")
    # Historical cleanup is a recorded observation. A copied archive is valid;
    # its containing directory must not be confused with the original /tmp run.
    return {"owned_wait4_children": 10, "joined_proxy_listeners": 5, "private_cleanup": "historical original observation verified",
            "resident_quarantine_basis": "one source-bound control worker; last four M calls same Scope; no restart/intervening call",
            "M_lifetime": {"service_start_ns": stamp(services["M"]["start"]), "service_wait4_ns": stamp(services["M"]["stop"]),
                           "proxy_join_ns": stamp(m_close), "event_sequences": [services["M"]["start"]["sequence"], services["M"]["stop"]["sequence"], m_close["sequence"]]}}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()


def git_tree(files):
    tree = {}
    for row in files:
        parts = PurePosixPath(row["path"]).parts
        current = tree
        for part in parts[:-1]:
            current = current.setdefault(part, {})
            require(type(current) is dict, "source path conflicts with a file")
        require(parts[-1] not in current, "duplicate/conflicting source path")
        current[parts[-1]] = (row["mode"], row["git_blob"])
    def digest(directory):
        contents = bytearray()
        for name in sorted(directory, key=lambda key: (key + ("/" if isinstance(directory[key], dict) else "")).encode()):
            value = directory[name]
            mode, oid = ("40000", digest(value)) if isinstance(value, dict) else value
            contents.extend(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
        return hashlib.sha1(b"tree " + str(len(contents)).encode() + b"\0" + contents).hexdigest()
    return digest(tree)


def source_proof(directory):
    directory = Path(directory)
    manifest_raw = (directory / "metadata-source-before.json").read_bytes()
    require(len(manifest_raw) <= 4 * 1024 * 1024, "frozen source manifest exceeds bound")
    manifest = parse(manifest_raw)
    require(set(manifest) == {"schema_version", "scope", "commit", "tree", "files", "source_sha256"} and
            type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and
            manifest["scope"] == "git-tracked-source-only", "fixture source capture shape changed")
    require(all(type(manifest[key]) is str and re.fullmatch(r"[0-9a-f]{40}", manifest[key]) for key in ("commit", "tree")), "fixture source Git identity changed")
    files = manifest["files"]
    require(type(files) is list and files, "empty frozen source inventory")
    for row in files:
        require(set(row) == {"path", "mode", "git_blob", "bytes", "sha256"}, "frozen source entry fields changed")
        path = PurePosixPath(row["path"])
        require(path.as_posix() == row["path"] and not path.is_absolute() and ".." not in path.parts and row["path"] != "." and
                "\\" not in row["path"] and row["mode"] in ("100644", "100755") and type(row["bytes"]) is int and 0 <= row["bytes"] <= 16 * 1024 * 1024 and
                type(row["git_blob"]) is str and re.fullmatch(r"[0-9a-f]{40}", row["git_blob"]), "invalid frozen source entry")
        WIRE.sha256_text(row["sha256"])
    names = [row["path"] for row in files]
    require(names == sorted(set(names)) and sha(canonical(files)) == manifest["source_sha256"] and git_tree(files) == manifest["tree"],
            "source inventory/hash/Git tree differs")
    archived = parse((directory / "metadata-source-archive.json").read_bytes())
    require(set(archived) == {"schema", "commit", "tree", "sha256", "bytes"} and archived["schema"] == 1 and
            archived["commit"] == manifest["commit"] and archived["tree"] == manifest["tree"] and
            type(archived["bytes"]) is int and (directory / "metadata-source.tar").stat().st_size == archived["bytes"] and
            BUILD.file_digest(directory / "metadata-source.tar") == archived["sha256"], "fixture source archive identity differs")
    required = {"experiments/object-metadata/" + name for name in ("oracle.py", "controls.py", "test_oracle.py", "test_cleanup.py", "README.md", "run.py", "probe.mjs", "proxy.py", "fixture_spec.py")}
    required |= {"experiments/object-service/" + name for name in ("client_ledger.mjs", "client_transport.mjs", "audit_wire.py")}
    required |= {"experiments/object-network/" + name for name in ("head5_audit.py", "audit_build.py")}
    require(required <= set(names), "source archive omitted actual fixture/independent checker/observer inputs")
    by_name = {row["path"]: row for row in files}
    total = 0
    with tarfile.open(directory / "metadata-source.tar", mode="r:") as archive:
        members = archive.getmembers()
        regular = [member for member in members if member.isfile()]
        require(all(member.isfile() or member.isdir() for member in members) and
                len(regular) == len(files) and {member.name for member in regular} == set(names), "fixture source archive members changed")
        for member in regular:
            expected = by_name[member.name]
            require(member.size == expected["bytes"] and ("100755" if member.mode & 0o111 else "100644") == expected["mode"], "source archive extent/mode differs")
            with archive.extractfile(member) as stream:
                raw = stream.read()
            require(sha(raw) == expected["sha256"] and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected["git_blob"],
                    "archived source differs from exact committed blob")
            if member.name in required:
                equal((ROOT / member.name).read_bytes(), raw, "running fixture/oracle/helper differs from frozen source")
            total += len(raw)
    log = (directory / "metadata-source-after.log").read_text()
    require(log == "PASS: source identity matches " + manifest["commit"] + "; test verdicts are separate\n", "source identity was not verified after the original run")
    require((directory / "metadata-source-before.log").read_text() ==
            f"CAPTURED: {manifest['commit']} tree={manifest['tree']}; {len(files)} files\n" and
            (directory / "metadata-source-archive.stderr.log").read_bytes() == b"", "source capture/archive command did not preserve clean completion")
    build_value = parse((directory / "daemon-build-evidence/build-receipt.json").read_bytes())
    require(all(name in by_name and by_name[name]["sha256"] == digest for name, digest in build_value["inputs"].items()),
            "fixture source differs from original daemon/SDK build inputs")
    return {"commit": manifest["commit"], "tree": manifest["tree"], "source_sha256": manifest["source_sha256"],
            "files": len(files), "bytes": total, "manifest_sha256": sha(manifest_raw), "archive_sha256": archived["sha256"],
            "daemon_build_commit": build_value["source_commit"], "daemon_inputs_equal": True}


RAW_FILES = ["metadata-plan.json", "metadata-configuration.json", "metadata-tools.json", "service-S.json", "service-M.json",
             "events.jsonl", "http-proxy.jsonl", "s3.jsonl", "metadata-node.jsonl", "http-client-ledger.jsonl", "http-client-transport.jsonl",
             "service-S.log", "service-M.log", "node.stderr.log", "metadata-source-before.json", "metadata-source-before.log", "metadata-source-after.log",
             "metadata-source-archive.json", "metadata-source-archive.stderr.log", "metadata-source.tar",
             *["backend-" + role + ".log" for role in ("master", "volume", "filer", "s3")],
             *["request-" + name + ".json" for name in NAMES],
             *[name + "." + suffix for name in MAINTENANCE for suffix in ("headers", "body", "stdout", "stderr")],
             *["daemon-build-evidence/" + name for name in ("build-receipt.json", "build-source-manifest.json", "build-source.tar", "build-cargo.stdout.jsonl", "build-cargo.stderr.log")]]


def evidence_inventory(directory):
    directory = Path(directory)
    result = []
    for name in sorted(RAW_FILES):
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "missing/nonregular original evidence: " + name)
        result.append({"path": name, "bytes": path.stat().st_size, "sha256": BUILD.file_digest(path)})
    return result


def audit(directory, require_artifacts=True, *, include_projection=False):
    directory = Path(directory)
    before = evidence_inventory(directory)
    source = source_proof(directory)
    build = BUILD.receipt(directory / "daemon-build-evidence", profile="service", require_artifacts=require_artifacts, source_root=ROOT)
    config, configs = load_configuration(directory)
    plan_sha = plan_proof(directory)
    events = rows(directory, "events.jsonl")
    s3_trace = rows(directory, "s3.jsonl")
    http_trace = rows(directory, "http-proxy.jsonl")
    node, operations, _saved = node_proof(directory, events)
    calls, http_handlers = http_proof(directory, http_trace, operations, config, node)
    observation = observer_proof(directory, calls)
    exchanges, s3_handlers = s3_exchanges(s3_trace, config)
    process = process_proof(directory, events, node, calls, http_handlers, s3_handlers, config, configs, build)
    versions = normal_versions(exchanges)
    accepted, bases, _objects, closures = head_history(exchanges, calls)
    fault = fault_and_repair_proof(directory, events, exchanges, calls, bases, accepted)
    projection = metadata_projection(exchanges, calls, bases, accepted, config, process)
    metadata = metadata_semantics(projection)
    equal(evidence_inventory(directory), before, "original evidence changed during independent audit")
    result = {"schema": 1, "status": "passed", "profile": "independent-metadata-head-only-real-transport-v1",
              "verification_scope": "full" if require_artifacts else "explicit_offline_artifact_diagnostic",
              "source": source, "daemon_build": build, "plan_sha256": plan_sha,
              "offered_commands": 41, "http_by_worker": {"S": 28, "M": 13}, "original_sql_acks": 6,
              "normal_head_publications": 28, "declared_fault_head_writes": 2,
              "s3_by_worker": dict(Counter(item["request"]["worker"] for item in exchanges)),
              "metadata": metadata, "faults": fault, "process": process, "transport_observation": observation,
              "object_versions": versions, "seed_closures": closures,
              "evidence_inventory": before, "evidence_sha256": sha(canonical(before)),
              "projection_sha256": sha(canonical(projection)),
              "limits": ["Local compatible endpoint only; AWS Standard NOT_RUN", "No throughput/SLO conclusion",
                         "Zero M immutable I/O is not payload/native health proof", "No per-HTTP S3 interval attribution",
                         "Metadata ACK proves the original HEAD CAS only", "Resident latch proof relies on frozen single-control-worker lifecycle",
                         "No generation promotion/GC/DELETE/controller activation"]}
    if include_projection:
        return result, projection
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-missing-build-artifacts", action="store_true", help="explicit offline diagnostic only; never formal acceptance")
    args = parser.parse_args()
    try:
        value = audit(args.evidence, require_artifacts=not args.allow_missing_build_artifacts)
        code = 0
    except (ValueError, OSError, KeyError, TypeError, IndexError, tarfile.TarError) as error:
        value, code = {"schema": 1, "status": "failed", "error_type": type(error).__name__, "error": str(error)}, 1
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
    print(encoded, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
