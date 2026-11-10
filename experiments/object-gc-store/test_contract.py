"""Small independent checks for the auditor's byte/signature/status handling."""
import hashlib
import hmac
import http.client
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

import oracle
from plan import PREFIX, cases
from proxy import Call, Proxy, mutation
from support import Log, body_record, body_value, rows, signature_input, signing_key, verify_signature
from run import Worker


class ContractTests(unittest.TestCase):
    def test_raw_bytes_are_checked(self):
        record = body_record(b"\0binary\xff")
        self.assertEqual(body_value(record), b"\0binary\xff")
        record["bytes"] += 1
        with self.assertRaises(AssertionError):
            body_value(record)

    def test_signature_binds_method_target_body_and_original_etag(self):
        target, access, secret = "/scap-test/" + PREFIX + "a" * 64, "fixture-access", "fixture-secret"
        scope = "20261108/us-east-1/s3/aws4_request"
        headers = {"host": "127.0.0.1:1234", "x-amz-date": "20261108T120000Z",
                   "if-match": '"original"', "x-amz-content-sha256": hashlib.sha256(b"").hexdigest()}
        signed = ";".join(sorted(headers))
        canonical = signature_input("DELETE", target, headers, b"", signed)
        value = "\n".join(("AWS4-HMAC-SHA256", headers["x-amz-date"], scope,
                           hashlib.sha256(canonical).hexdigest())).encode()
        signature = hmac.new(signing_key(secret, scope), value, hashlib.sha256).hexdigest()
        headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={signature}"
        self.assertTrue(verify_signature("DELETE", target, headers, b"", access, secret))
        for method, url, changed, credential in (
            ("GET", target, headers, secret), ("DELETE", target + "b", headers, secret),
            ("DELETE", target, {**headers, "if-match": '"new-etag"'}, secret),
            ("DELETE", target, headers, "wrong-secret"),
        ):
            self.assertFalse(verify_signature(method, url, changed, b"", access, credential))

    def test_blank_query_value_is_signed(self):
        headers = {"host": "127.0.0.1:1234"}
        self.assertEqual(signature_input("GET", "/bucket?versioning", headers, b"", "host"),
                         signature_input("GET", "/bucket?versioning=", headers, b"", "host"))

    def test_status_does_not_prove_physical_absence(self):
        def response(status, body=b"", headers=None, extra=0):
            return {"status": status, "body": body_record(body), "headers": headers or {},
                    "declared_length": len(body) + extra}
        for value, expected in (
            (response(204), "Applied"), (response(412), "Conflict"), (response(403), "Denied"),
            (response(204, headers={"x-amz-delete-marker": "true"}), "Unknown"),
            (response(204, headers={"x-amz-version-id": "v1"}), "Unknown"),
            (response(204, extra=1), "Unknown"), (response(409), "Unknown"),
            (response(200), "Unknown"), (response(500, b" " * 32769), "Unknown"),
            (response(404, b"<Error><Code>NoSuchKey</Code></Error>"), "Missing"),
            (response(404, b"<Error><Code>NoSuchBucket</Code></Error>"), "Unknown"),
            (response(404, b"invalid XML"), "Unknown"),
        ):
            with self.subTest(expected=expected, status=value["status"]):
                self.assertEqual(oracle.deletion(value), expected)

    def test_oversize_fault_does_not_depend_on_illegal_204_body(self):
        status, _, body, extra = mutation("oversize", {"status": 204, "headers": {}, "bytes": b""})
        self.assertEqual((status, len(body), extra), (500, 32769, 0))

    def test_plan_has_fixed_denominator_and_no_duplicate_names(self):
        plan = cases()
        self.assertEqual(len(plan), 42)
        self.assertEqual(len({item["name"] for item in plan}), 42)
        self.assertEqual(sum(item["requests"] for item in plan), 115)
        self.assertEqual(next(item for item in plan if item["kind"] == "budget")["outcomes"],
                         ["Applied"] * 32 + ["Limit"])

    def test_child_registered_before_start_log_failure(self):
        class FailingStartLog:
            def __init__(self):
                self.stops = []

            def write(self, event, **fields):
                if event == "worker_started":
                    raise OSError("injected start log failure")
                self.stops.append((event, fields))

        with tempfile.TemporaryDirectory(prefix="scap-gc-fixture-child-") as raw:
            directory = Path(raw)
            binary = directory / "waiting-child"
            binary.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdin.buffer.read()\n")
            binary.chmod(0o700)
            log, owned = FailingStartLog(), {}
            try:
                with self.assertRaisesRegex(OSError, "injected start log failure"):
                    Worker(binary, directory, "test-bucket", SimpleNamespace(access="fixture", secret="fixture"),
                           "http://127.0.0.1:1", directory, log, owned)
                self.assertEqual(set(owned), {"test-bucket"})
            finally:
                for worker in owned.values():
                    self.assertEqual(worker.close(), 0)
            self.assertEqual(len(log.stops), 1)
            self.assertEqual(log.stops[0][1]["kernel_usage"]["source"], "kernel_wait4_owned_child")

    def test_declared_fault_requires_delivered_bytes(self):
        original = {"status": 204, "headers": {}, "body": body_record(b"")}
        delivered = {"status": 200, "headers": {}, "body": body_record(b""), "declared_length": 0}
        oracle.fault_delivery("status_200", "delete", original, delivered)
        delivered["status"] = 204
        with self.assertRaises(AssertionError):
            oracle.fault_delivery("status_200", "delete", original, delivered)

    def test_unexpected_http_methods_are_observed_and_rejected(self):
        with tempfile.TemporaryDirectory(prefix="scap-gc-fixture-methods-") as raw:
            log = Log(Path(raw) / "history.jsonl")
            proxy = Proxy(SimpleNamespace(port=1, access="fixture", secret="fixture"), log)
            proxy.current = Call("unexpected_method_negative_control")
            try:
                for method in ("HEAD", "POST", "SCAPUNEXPECTED"):
                    connection = http.client.HTTPConnection("127.0.0.1", proxy.server.server_port, timeout=2)
                    try:
                        connection.request(method, "/must-be-recorded", body=b"")
                        response = connection.getresponse()
                        self.assertEqual(response.status, 501)
                        self.assertEqual(response.read(), b"")
                    finally:
                        connection.close()
            finally:
                proxy.close()
            self.assertEqual(len(proxy.errors), 3)
            self.assertEqual(proxy.current.requests, 3)
            observed = rows(log.path)
            self.assertEqual([item["method"] for item in observed if item["event"] == "unexpected_http"],
                             ["HEAD", "POST", "SCAPUNEXPECTED"])
            self.assertEqual(len([item for item in observed if item["event"] == "fixture_error"]), 3)


if __name__ == "__main__":
    unittest.main()
