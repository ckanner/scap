#!/usr/bin/env python3
"""Signed SeaweedFS LIST pages, bounded response faults, and an independent audit.

No SQLite, directory classifier, public cursor, tenant ACL, recovery-complete,
or AWS cloud claim is made by this storage-port contract.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import http.client
import http.server
import json
from pathlib import Path
import re
import select
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qsl, quote, urlsplit
import xml.etree.ElementTree as ET

import listing_build
import run as fixture

LIMIT = 1024 * 1024
PREFIX = "n2-a/flat/"
CHILDREN = "n2-a/children/"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
FAULTS = {
    "missing_truncation": "Corrupt", "wrong_count": "Corrupt",
    "wrong_prefix": "Corrupt", "wrong_max_keys": "Corrupt",
    "missing_token": "Corrupt", "false_complete": "Corrupt",
    "duplicate_entry": "Corrupt", "reversed": "Corrupt",
    "outside_key": "Corrupt", "no_progress": "Corrupt",
    "after_ignored": "Corrupt", "malformed_xml": "Corrupt",
    "oversized": "Limit", "error_oversized": "Unknown",
    "deadline": "Unknown", "short_body": "Unknown",
    "redirect": "Unknown",
}


def hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def body_record(value):
    return {"bytes": len(value), "sha256": hash_bytes(value),
            "base64": base64.b64encode(value).decode()}


def body_value(record):
    value = base64.b64decode(record["base64"], validate=True)
    assert len(value) == record["bytes"] and hash_bytes(value) == record["sha256"]
    return value


def verify_signature(method, target, headers, payload, access, secret):
    authorization = headers.get("Authorization", "")
    match = re.fullmatch(r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([0-9a-f]{64})", authorization)
    if match is None:
        return False
    actual_access, scope, signed, signature = match.groups()
    if actual_access != access:
        return False
    date, region, service, suffix = scope.split("/")
    assert (region, service, suffix) == ("us-east-1", "s3", "aws4_request")
    names = signed.split(";")
    assert names == sorted(set(names)) and "host" in names
    canonical_headers = "".join(f"{name}:{' '.join(headers[name].split())}\n" for name in names)
    parsed = urlsplit(target)
    query = "&".join(f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
                     for key, value in sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    payload_hash = headers.get("x-amz-content-sha256", hash_bytes(payload))
    assert payload_hash in ("UNSIGNED-PAYLOAD", hash_bytes(payload))
    canonical = "\n".join((method, parsed.path, query, canonical_headers, signed, payload_hash)).encode()
    signed_value = "\n".join(("AWS4-HMAC-SHA256", headers["x-amz-date"], scope, hash_bytes(canonical))).encode()
    key = ("AWS4" + secret).encode()
    for component in (date, region, service, suffix):
        key = hmac.new(key, component.encode(), hashlib.sha256).digest()
    expected = hmac.new(key, signed_value, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def replace_once(body, pattern, replacement):
    result, count = re.subn(pattern, replacement, body, count=1, flags=re.DOTALL)
    assert count == 1, f"fault target missing: {pattern!r}"
    return result


def mutate(body, mode, after):
    status, extra, delay = 200, 0, 0
    if mode is None:
        return status, body, extra, delay
    if mode == "missing_truncation":
        body = replace_once(body, rb"<IsTruncated>.*?</IsTruncated>", b"")
    elif mode == "wrong_count":
        body = replace_once(body, rb"<KeyCount>.*?</KeyCount>", b"<KeyCount>0</KeyCount>")
    elif mode == "wrong_prefix":
        body = replace_once(body, rb"<Prefix>.*?</Prefix>", b"<Prefix>other/</Prefix>")
    elif mode == "wrong_max_keys":
        body = replace_once(body, rb"<MaxKeys>.*?</MaxKeys>", b"<MaxKeys>1000</MaxKeys>")
    elif mode == "missing_token":
        body = replace_once(body, rb"<NextContinuationToken>.*?</NextContinuationToken>", b"")
    elif mode == "false_complete":
        body = replace_once(body, rb"<IsTruncated>true</IsTruncated>", b"<IsTruncated>false</IsTruncated>")
    elif mode in ("duplicate_entry", "reversed"):
        entries = re.findall(rb"<Contents>.*?</Contents>", body, flags=re.DOTALL)
        assert len(entries) >= 2
        if mode == "duplicate_entry":
            body = body.replace(entries[1], entries[0], 1)
        else:
            assert entries[0] + entries[1] in body
            body = body.replace(entries[0] + entries[1], entries[1] + entries[0], 1)
    elif mode in ("outside_key", "after_ignored"):
        key = b"outside/key" if mode == "outside_key" else after.encode()
        body = replace_once(body, rb"<Key>.*?</Key>", b"<Key>" + key + b"</Key>")
    elif mode == "no_progress":
        body = re.sub(rb"<Contents>.*?</Contents>", b"", body, flags=re.DOTALL)
        body = replace_once(body, rb"<KeyCount>.*?</KeyCount>", b"<KeyCount>0</KeyCount>")
    elif mode == "malformed_xml":
        body = body[:-20]
    elif mode in ("oversized", "error_oversized"):
        body = b" " * (LIMIT + 1)
        if mode == "error_oversized":
            status = 500
    elif mode == "at_limit":
        assert len(body) < LIMIT
        body += b" " * (LIMIT - len(body))
    elif mode == "deadline":
        delay = 0.25
    elif mode == "short_body":
        extra = 10
    elif mode == "redirect":
        status, body = 307, b""
    else:
        raise AssertionError(f"unknown fault {mode}")
    return status, body, extra, delay


class Log:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()

    def write(self, event, **fields):
        with self.lock:
            fixture.append_synced(self.path, {"event": event, "at_ns": time.monotonic_ns(), **fields})


class Proxy:
    def __init__(self, backend, log):
        self.backend, self.log = backend, log
        self.current = None
        self.errors = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.forward()

            def do_PUT(self):
                self.forward()

            def forward(self):
                call = owner.current
                self.close_connection = True
                connection = None
                try:
                    assert call is not None, "unrequested storage HTTP call"
                    started = time.monotonic_ns()
                    length = int(self.headers.get("Content-Length", "0"))
                    assert 0 <= length <= 1024
                    payload = self.rfile.read(length)
                    assert len(payload) == length
                    auth = verify_signature(self.command, self.path, self.headers, payload,
                                            backend.access, backend.secret)
                    connection = http.client.HTTPConnection("127.0.0.1", backend.port, timeout=5)
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in self.headers.items():
                        connection.putheader(name, value)
                    connection.endheaders(payload)
                    response = connection.getresponse()
                    original = response.read(LIMIT + 1)
                    assert len(original) <= LIMIT, "backend fixture response unexpectedly large"
                    received = time.monotonic_ns()
                    mode = call["mode"]
                    if mode:
                        assert response.status == 200
                        assert mode == "redirect" or "list-type=2" in self.path
                        status, delivered, extra, delay = mutate(original, mode, call["after"])
                    else:
                        status, delivered, extra, delay = response.status, original, 0, 0
                    time.sleep(delay)
                    attempted = time.monotonic_ns()
                    complete = False
                    try:
                        self.send_response_only(status)
                        for name, value in response.getheaders():
                            if name.lower() not in {"content-length", "connection", "transfer-encoding"}:
                                self.send_header(name, value)
                        self.send_header("Content-Length", str(len(delivered) + extra))
                        if mode == "redirect":
                            self.send_header("Location", self.path)
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(delivered)
                        self.wfile.flush()
                        complete = True
                    except (BrokenPipeError, ConnectionResetError):
                        # A rejected or expired page can close its transport early.
                        pass
                    owner.log.write("http", id=call["id"], method=self.command, target=self.path,
                                    request=body_record(payload), signature_valid=auth,
                                    if_none_match=self.headers.get("If-None-Match"),
                                    backend_status=response.status, backend_body=body_record(original),
                                    delivered_status=status, attempted_body=body_record(delivered),
                                    location=self.path if mode == "redirect" else None,
                                    declared_length=len(delivered) + extra, fault=mode,
                                    write_completed=complete, request_started_ns=started,
                                    backend_response_ns=received, delivery_attempt_ns=attempted)
                except BaseException as error:
                    owner.errors.append(repr(error))
                    owner.log.write("fixture_error", error=repr(error))
                finally:
                    if connection is not None:
                        connection.close()
                    if call is not None:
                        call["finished"].set()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        assert not self.thread.is_alive()


class Worker:
    def __init__(self, binary, directory, label, backend, endpoint, bucket="scap-test", bad_secret=False):
        config = directory / f"{label}.private.json"
        config.write_text(json.dumps({"endpoint": endpoint, "bucket": bucket,
                                     "access_key": backend.access,
                                     "secret_key": "invalid-secret" if bad_secret else backend.secret}))
        config.chmod(0o600)
        self.label = label
        self.stderr = (directory / f"{label}.private.log").open("wb")
        self.process = subprocess.Popen([str(binary), str(config)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr, text=True, bufsize=1)
        self.identity = fixture.process_identity(self.process)
        hello = self.read()
        assert hello == {"ready": True, "max_entries": 32, "max_response_bytes": LIMIT}

    def read(self):
        assert select.select([self.process.stdout], [], [], 8)[0], "worker output deadline"
        line = self.process.stdout.readline()
        assert line.endswith("\n"), "worker closed or truncated response"
        return json.loads(line)

    def close(self):
        self.process.stdin.close()
        try:
            code, usage = fixture.wait_child(self.process, 8)
        except TimeoutError:
            self.process.kill()
            code, usage = fixture.wait_child(self.process, 8)
        self.process.stdout.close()
        self.stderr.close()
        return {"label": self.label, **self.identity, "wait_status": code, "kernel_usage": usage}


def expected_entries(keys, prefix, children):
    entries = {}
    for key in keys:
        if not key.startswith(prefix):
            continue
        suffix = key[len(prefix):]
        if children and "/" in suffix:
            entries[prefix + suffix.split("/", 1)[0] + "/"] = "prefix"
        else:
            entries[key] = "object"
    return [{"key": key, "kind": entries[key]} for key in sorted(entries, key=lambda value: value.encode())]


def parsed_page(body, command):
    root = ET.fromstring(body)
    assert root.tag == NS + "ListBucketResult"
    scalar = lambda name: root.findtext(NS + name)
    assert scalar("Name") == "scap-test" and scalar("Prefix") == command["prefix"]
    assert scalar("MaxKeys") == "32" and scalar("StartAfter") == command["after"]
    assert scalar("Delimiter") == ("/" if command["children"] else None)
    objects = [{"key": item.findtext(NS + "Key"), "kind": "object"} for item in root.findall(NS + "Contents")]
    prefixes = [{"key": item.findtext(NS + "Prefix"), "kind": "prefix"} for item in root.findall(NS + "CommonPrefixes")]
    for sequence in (objects, prefixes):
        assert [entry["key"] for entry in sequence] == sorted({entry["key"] for entry in sequence}, key=lambda value: value.encode())
    entries = sorted(objects + prefixes, key=lambda item: item["key"].encode())
    assert len(entries) <= 32 and scalar("KeyCount") == str(len(entries))
    for entry in entries:
        assert entry["key"].startswith(command["prefix"])
        assert command["after"] is None or entry["key"].encode() > command["after"].encode()
        suffix = entry["key"][len(command["prefix"]):]
        assert suffix
        if entry["kind"] == "prefix":
            assert command["children"] and suffix.endswith("/") and "/" not in suffix[:-1]
        elif command["children"]:
            assert "/" not in suffix
    if scalar("IsTruncated") == "true":
        token = scalar("NextContinuationToken")
        assert entries and token and len(token.encode()) <= 4096
        end = {"kind": "more", "after": entries[-1]["key"]}
    else:
        assert scalar("IsTruncated") == "false" and scalar("NextContinuationToken") is None
        end = {"kind": "exhausted"}
    return entries, end


def audit(records):
    assert all(type(row.get("id")) is int for row in records if row["event"] in {"call", "reply", "http"})
    calls = {row["id"]: row for row in records if row["event"] == "call"}
    replies = {row["id"]: row for row in records if row["event"] == "reply"}
    http = {}
    for row in records:
        if row["event"] == "http":
            assert row["id"] not in http, "hidden retry or duplicate HTTP attempt"
            http[row["id"]] = row
    assert calls and set(calls) == set(replies) == set(http), "call/response/HTTP inventory mismatch"
    assert len(calls) == sum(row["event"] == "call" for row in records), "duplicate call ID"
    assert len(replies) == sum(row["event"] == "reply" for row in records), "duplicate reply ID"
    assert set(calls) == set(range(1, len(calls) + 1)), "omitted invocation"
    assert not any(row["event"] == "fixture_error" for row in records)
    durable, scans, seen_faults, cases = {}, {}, set(), set()
    list_pages = 0
    for identity in sorted(calls):
        call, returned, wire = calls[identity], replies[identity], http[identity]
        command, result = call["command"], returned["result"]
        assert command["id"] == result["id"] == identity
        assert call["at_ns"] < returned["at_ns"] and wire["request_started_ns"] < returned["at_ns"]
        request = body_value(wire["request"])
        original, delivered = body_value(wire["backend_body"]), body_value(wire["attempted_body"])
        case = call["case"]
        cases.add(case)
        assert wire["signature_valid"] is (case != "real_bad_signature")
        parsed = urlsplit(wire["target"])
        if case in ("redirect_get", "redirect_put"):
            assert wire["method"] == command["op"].upper() and wire["fault"] == "redirect"
            assert parsed.path == "/scap-test/" + command["key"] and not parsed.query
            assert wire["backend_status"] == 200 and wire["delivered_status"] == 307
            assert delivered == b"" and wire["declared_length"] == 0
            assert wire["location"] == wire["target"]
            assert result == {"id": identity, "ok": False, "error": "Unknown"}
            if command["op"] == "put":
                assert request == command["value"].encode() and wire["if_none_match"] == "*"
                durable[command["key"]] = command["value"]
            else:
                assert request == b"" and original == durable[command["key"]].encode()
            continue
        if command["op"] == "put":
            assert wire["method"] == "PUT" and wire["if_none_match"] == "*"
            assert request == command["value"].encode() and wire["backend_status"] == 200
            assert result["ok"] is True and result["etag"]
            assert parsed.path == "/scap-test/" + quote(command["key"], safe="/-_.~")
            durable[command["key"]] = command["value"]
            continue
        if command["op"] == "get":
            assert wire["method"] == "GET" and wire["backend_status"] == 200 and not parsed.query
            assert result["ok"] is True and bytes(result["bytes"]) == durable[command["key"]].encode() == original
            continue
        list_pages += 1
        assert wire["method"] == "GET" and request == b""
        expected_query = {"list-type": "2", "max-keys": "32", "prefix": command["prefix"]}
        if command["children"]:
            expected_query["delimiter"] = "/"
        if command["after"] is not None:
            expected_query["start-after"] = command["after"]
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        assert len(pairs) == len(expected_query) and dict(pairs) == expected_query, "HTTP intent differs from invocation"
        mode = wire["fault"]
        if case in ("real_bad_signature", "real_missing_bucket"):
            status = 403 if case == "real_bad_signature" else 404
            assert mode is None and wire["backend_status"] == wire["delivered_status"] == status
            assert result == {"id": identity, "ok": False, "error": "Denied" if status == 403 else "Unknown"}
            continue
        assert parsed.path == "/scap-test" and wire["backend_status"] == 200
        parsed_page(original, command)
        status, mutated, extra, _ = mutate(original, mode, command["after"])
        assert status == wire["delivered_status"] and mutated == delivered
        assert wire["declared_length"] == len(delivered) + extra
        if mode in FAULTS:
            assert case == mode and mode not in seen_faults
            seen_faults.add(mode)
            assert result == {"id": identity, "ok": False, "error": FAULTS[mode]}, "corrupt or unavailable page returned success"
            if mode == "deadline":
                assert returned["at_ns"] < wire["delivery_attempt_ns"], "deadline did not precede held response"
            if mode == "redirect":
                assert wire["location"] == wire["target"], "redirect lacks its actual Location target"
            continue
        assert mode in (None, "at_limit") and result["ok"] is True
        entries, end = parsed_page(delivered, command)
        assert result == {"id": identity, "ok": True, "entries": entries, "end": end, "response_bytes": len(delivered)}
        assert len(delivered) <= LIMIT and wire["write_completed"]
        if mode == "at_limit":
            assert len(delivered) == LIMIT
        if case.endswith("-inventory"):
            state = scans.setdefault(case, {"expected": expected_entries(durable, command["prefix"], command["children"]), "entries": [], "after": None, "done": False})
            assert not state["done"] and command["after"] == state["after"], "skipped or repeated scan frontier"
            state["entries"].extend(entries)
            state["after"] = end.get("after")
            if end["kind"] == "exhausted":
                assert state["entries"] == state["expected"], "complete inventory omitted permanent candidates"
                state["done"] = True
    assert seen_faults == set(FAULTS), "missing negative control"
    assert set(scans) == {"flat-inventory", "children-inventory", "rescan-inventory"}
    assert all(state["done"] for state in scans.values())
    assert {"empty", "at_limit", "online-first", "online-rest", "exact-get", "after-errors",
            "real_bad_signature", "real_missing_bucket", "redirect_get", "redirect_put", "redirect_put_verify"} <= cases
    online = [replies[identity]["result"] for identity in calls if calls[identity]["case"] in ("online-first", "online-rest")]
    online_keys = [entry["key"] for page in online for entry in page["entries"]]
    assert PREFIX + "!behind" not in online_keys and PREFIX + "zz-ahead" in online_keys
    assert online[-1]["end"] == {"kind": "exhausted"}
    assert PREFIX + "!behind" in [entry["key"] for entry in scans["rescan-inventory"]["entries"]]
    backend = [row for row in records if row["event"] == "backend_stopped"]
    workers = [row for row in records if row["event"] == "worker_stopped"]
    assert len(backend) == 1 and len(backend[0]["children"]) == 4
    assert len(workers) == 3 and {row["child"]["label"] for row in workers} == {"main", "bad-secret", "missing-bucket"}
    for child in backend[0]["children"] + [row["child"] for row in workers]:
        assert child["pid_source"] == "owned_Popen_child"
        assert child["kernel_usage"]["source"] == "kernel_wait4_owned_child"
    assert all(child["wait_status"] == -9 for child in backend[0]["children"])
    assert all(row["child"]["wait_status"] == 0 for row in workers)
    return {"status": "passed", "scope": "N2-A-storage-port-only", "calls": len(calls),
            "list_calls": list_pages, "negative_controls": len(seen_faults) + 4,
            "complete_inventory_scans": len(scans), "observed_online_non_snapshot": True}


def run(args):
    receipt = listing_build.verify(args.build_receipt, args.worker)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    log = Log(evidence / "listing-history.jsonl")
    log.write("inputs", build_receipt=str(args.build_receipt.resolve()),
              build_receipt_sha256=listing_build.digest(args.build_receipt), binary=receipt["binary"],
              backend={"path": str(args.weed.resolve()), "sha256": listing_build.digest(args.weed)},
              source_sha256=receipt["input_sha256"])
    result = {"status": "failed", "scope": "N2-A-storage-port-only"}
    try:
        with tempfile.TemporaryDirectory(prefix="listing-private-", dir=evidence.parent) as temporary:
            private = Path(temporary)
            backend = fixture.Backend(args.weed.resolve(), private / "backend")
            proxy, workers = None, []
            try:
                backend.start()
                proxy = Proxy(backend, log)
                for label, options in (("main", {}), ("bad-secret", {"bad_secret": True}),
                                       ("missing-bucket", {"bucket": "scap-absent-listing-bucket"})):
                    worker = Worker(args.worker.resolve(), private, label, backend, proxy.endpoint, **options)
                    workers.append(worker)
                    log.write("worker_started", label=label, child=worker.identity)
                serial = 0

                def call(case, op="list", worker=workers[0], mode=None, **values):
                    nonlocal serial
                    serial += 1
                    command = {"id": serial, "op": op, **values}
                    if op == "list":
                        command = {"prefix": PREFIX, "children": False, "after": None, "deadline_ms": 3000, **command}
                    current = {"id": serial, "mode": mode, "after": command.get("after"), "finished": threading.Event()}
                    proxy.current = current
                    log.write("call", id=serial, case=case, worker=worker.label, command=command)
                    worker.process.stdin.write(json.dumps(command) + "\n")
                    worker.process.stdin.flush()
                    value = worker.read()
                    log.write("reply", id=serial, result=value)
                    assert value["id"] == serial
                    assert current["finished"].wait(6), "storage HTTP observation missing"
                    assert not proxy.errors, proxy.errors
                    return value

                def scan(case, prefix=PREFIX, children=False, after=None):
                    entries = []
                    for _ in range(16):
                        value = call(case, prefix=prefix, children=children, after=after)
                        assert value["ok"] is True, value
                        entries.extend(value["entries"])
                        if value["end"]["kind"] == "exhausted":
                            return entries
                        after = value["end"]["after"]
                    raise AssertionError("fixture inventory exceeded its explicit page budget")

                initial = [PREFIX + f"{index:03}" for index in range(65)] + [PREFIX + "é", PREFIX + "中"]
                initial += [CHILDREN + f"child-{index:03}/data" for index in range(65)]
                initial += [CHILDREN + "direct-a", CHILDREN + "direct-z"]
                for key in initial:
                    assert call("provision", op="put", key=key, value="data")["ok"] is True
                scan("flat-inventory")
                scan("children-inventory", CHILDREN, True)
                first = call("online-first")
                assert first["end"]["kind"] == "more"
                for suffix in ("!behind", "zz-ahead"):
                    assert call("concurrent-insert", op="put", key=PREFIX + suffix, value="data")["ok"]
                scan("online-rest", after=first["end"]["after"])
                scan("rescan-inventory")
                empty = call("empty", prefix="n2-a/empty/")
                assert empty["ok"] and not empty["entries"] and empty["end"]["kind"] == "exhausted"
                assert call("exact-get", op="get", key=PREFIX + "000")["ok"]
                assert call("at_limit", mode="at_limit")["ok"]
                for mode, error in FAULTS.items():
                    kwargs = {"after": PREFIX + "000"} if mode == "after_ignored" else {}
                    if mode == "deadline":
                        kwargs["deadline_ms"] = 30
                    value = call(mode, mode=mode, **kwargs)
                    assert value.get("ok") is False and value.get("error") == error, (mode, value)
                for case, worker, error in (("real_bad_signature", workers[1], "Denied"),
                                            ("real_missing_bucket", workers[2], "Unknown")):
                    value = call(case, worker=worker)
                    assert value.get("ok") is False and value.get("error") == error
                for case, op, key, values in (
                    ("redirect_get", "get", PREFIX + "000", {}),
                    ("redirect_put", "put", "n2-a/redirect/accepted", {"value": "accepted-once"}),
                ):
                    value = call(case, op=op, mode="redirect", key=key, **values)
                    assert value.get("ok") is False and value.get("error") == "Unknown"
                assert call("redirect_put_verify", op="get", key="n2-a/redirect/accepted")["ok"]
                assert call("after-errors")["ok"]
            finally:
                try:
                    for worker in workers:
                        log.write("worker_stopped", child=worker.close())
                finally:
                    try:
                        if proxy is not None:
                            proxy.close()
                    finally:
                        log.write("backend_stopped", children=backend.stop())
        records = [json.loads(line) for line in log.path.read_text().splitlines()]
        result = audit(records)
        listing_build.verify(args.build_receipt, args.worker)
        result["input_sha256"] = receipt["input_sha256"]
        result["history_sha256"] = listing_build.digest(log.path)
        result["binary"] = receipt["binary"]
        # Preserve semantic negative audit checks separately from transport faults.
        corruptions = []
        for mode in ("omit-call", "forged-success", "false-empty", "changed-frontier", "unauthenticated"):
            changed = copy.deepcopy(records)
            if mode == "omit-call":
                changed.pop(next(index for index, row in enumerate(changed) if row["event"] == "call"))
            elif mode == "forged-success":
                index = next(row["id"] for row in changed if row["event"] == "call" and row["case"] == "missing_truncation")
                next(row for row in changed if row["event"] == "reply" and row["id"] == index)["result"] = {"id": index, "ok": True, "entries": [], "end": {"kind": "exhausted"}, "response_bytes": 0}
            elif mode == "false-empty":
                row = next(row for row in changed if row["event"] == "reply" and row["result"].get("entries"))
                row["result"]["entries"] = []
            elif mode == "changed-frontier":
                row = next(row for row in changed if row["event"] == "call" and row["command"].get("after"))
                row["command"]["after"] = PREFIX + "wrong"
            else:
                next(row for row in changed if row["event"] == "http")["signature_valid"] = False
            try:
                audit(changed)
            except AssertionError:
                corruptions.append({"case": mode, "rejected": True})
            else:
                raise AssertionError(f"independent audit accepted {mode}")
        assert listing_build.digest(log.path) == result["history_sha256"]
        (evidence / "listing-audit-negatives.json").write_text(json.dumps(corruptions, indent=2) + "\n")
        result["audit_negative_controls"] = len(corruptions)
    except BaseException as error:
        result = {"status": "failed", "scope": "N2-A-storage-port-only", "error": repr(error)}
        raise
    finally:
        fixture.append_synced(evidence / "listing-oracle.json", result)
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--weed", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    run(parser.parse_args())
