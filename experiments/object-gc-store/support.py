"""Independent fixture I/O, SigV4 check and owned child observation."""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import importlib.util
import json
from pathlib import Path
import re
import threading
import time
from urllib.parse import parse_qsl, quote, urlsplit

if not __debug__:
    raise RuntimeError("contract requires assertions")

ROOT = Path(__file__).resolve().parents[2]
NETWORK = ROOT / "experiments" / "object-network"
spec = importlib.util.spec_from_file_location(
    "scap_gc_fixture_" + hashlib.sha256(str(ROOT).encode()).hexdigest()[:16],
    NETWORK / "run.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def body_record(value):
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest(),
            "base64": base64.b64encode(value).decode()}


def body_value(record):
    value = base64.b64decode(record["base64"], validate=True)
    assert body_record(value) == record, "body bytes differ from their raw record"
    return value


def rows(path):
    raw = Path(path).read_bytes()
    assert raw and raw.endswith(b"\n"), "missing or incomplete raw JSONL"
    return [json.loads(line) for line in raw.splitlines()]


class Log:
    def __init__(self, path):
        self.path, self.lock = Path(path), threading.Lock()

    def write(self, event, **fields):
        with self.lock:
            fixture.append_synced(self.path, {"event": event, "at_ns": time.monotonic_ns(), **fields})


def signing_key(secret, scope):
    key = ("AWS4" + secret).encode()
    for component in scope.split("/"):
        key = hmac.new(key, component.encode(), hashlib.sha256).digest()
    return key


def signature_input(method, target, headers, payload, signed):
    names = signed.split(";")
    assert names == sorted(set(names)) and "host" in names
    parsed = urlsplit(target)
    query = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
                     for k, v in sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    canonical_headers = "".join(f"{name}:{' '.join(headers[name].split())}\n" for name in names)
    payload_hash = headers.get("x-amz-content-sha256", hashlib.sha256(payload).hexdigest())
    assert payload_hash in ("UNSIGNED-PAYLOAD", hashlib.sha256(payload).hexdigest())
    return "\n".join((method, parsed.path, query, canonical_headers, signed, payload_hash)).encode()


def verify_signature(method, target, headers, payload, access, secret):
    headers = {name.lower(): value for name, value in headers.items()}
    match = re.fullmatch(
        r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([0-9a-f]{64})",
        headers.get("authorization", ""))
    if match is None:
        return False
    actual_access, scope, signed, signature = match.groups()
    components = scope.split("/")
    if actual_access != access or len(components) != 4 or components[1:] != ["us-east-1", "s3", "aws4_request"]:
        return False
    canonical = signature_input(method, target, headers, payload, signed)
    value = "\n".join(("AWS4-HMAC-SHA256", headers["x-amz-date"], scope,
                       hashlib.sha256(canonical).hexdigest())).encode()
    return hmac.compare_digest(hmac.new(signing_key(secret, scope), value, hashlib.sha256).hexdigest(), signature)


def signed_request(backend, method, target, payload=b"", extra=None):
    """Only fixture setup/independent observations; never product deletion."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    scope = stamp[:8] + "/us-east-1/s3/aws4_request"
    headers = {"host": f"127.0.0.1:{backend.port}", "x-amz-date": stamp,
               "x-amz-content-sha256": hashlib.sha256(payload).hexdigest(),
               **(extra or {})}
    signed = ";".join(sorted(headers))
    canonical = signature_input(method, target, headers, payload, signed)
    value = "\n".join(("AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical).hexdigest())).encode()
    signature = hmac.new(signing_key(backend.secret, scope), value, hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={backend.access}/{scope}, SignedHeaders={signed}, Signature={signature}"
    connection = http.client.HTTPConnection("127.0.0.1", backend.port, timeout=8)
    try:
        connection.request(method, target, body=payload, headers=headers)
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        assert len(body) <= 1024 * 1024, "fixture response bound"
        return {"status": response.status, "headers": dict(response.getheaders()), "body": body_record(body)}
    finally:
        connection.close()


def header(record, name):
    return next((value for key, value in record["headers"].items() if key.lower() == name.lower()), None)
