"""Handler-clock wiring and strict oracle controls; no product runtime is run."""
from __future__ import annotations

import copy
import hashlib
import hmac
import http.client
import io
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import discovery_oracle as audit
import discovery_proxy as proxy
from test_discovery_progress import call, zero_progress_fixture


def request(received=150, logged=300, *, tenant="7"):
    return {"event": "request", "monotonic_ns": logged,
            "request_received_monotonic_ns": received, "request_serial": 1,
            "key": f"scap-object/v1/1/{tenant}/key", "query": {}, "method": "GET"}


class ReceiptClockControls(unittest.TestCase):
    def test_missing_invalid_and_reversed_clocks_are_rejected(self):
        legacy = request()
        del legacy["request_received_monotonic_ns"]
        with self.assertRaisesRegex(ValueError, "missing its original receipt clock"):
            audit.received(legacy)
        for value in (None, True, "150", 0, -1, 1.5):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "invalid receipt clock"):
                audit.received(request(value))
        with self.assertRaisesRegex(ValueError, "follows its authenticated request log"):
            audit.received(request(301))
        self.assertEqual(audit.received(request(300)), 300)

    def test_authentication_delay_does_not_move_a_request_to_another_call(self):
        first = call(100, 200, None, {}, label="first")
        second = call(250, 400, None, {}, label="second")
        calls = {"first": first, "second": second}
        original = request(150, 300)
        before = copy.deepcopy(original)
        self.assertEqual(audit.request_owners(original, calls), ["first"])
        self.assertEqual(original, before)
        for value in (99, 100, 200, 220, 250, 400):
            with self.subTest(value=value):
                self.assertEqual(audit.request_owners(request(value, max(400, value)), calls), [])

    def test_earlier_clock_does_not_grant_another_scope_or_inventory_capability(self):
        ordinary = call(100, 200, None, {}, label="ordinary")
        foreign = request(150, 300, tenant="8")
        self.assertEqual(audit.request_owners(foreign, {"one": ordinary}), [])
        inventory = call(100, 200, None, {}, inventory=True, label="inventory")
        self.assertEqual(audit.request_owners(foreign, {"one": inventory}), ["inventory"])
        inventory["identity"]["deployment_inventory"] = False
        self.assertEqual(audit.request_owners(foreign, {"one": inventory}), [])

    def test_only_the_two_existing_held_labels_have_the_original_five_second_bound(self):
        for label in ("held_client_timeout", "held_client_abort", "ordinary"):
            current = call(100, 200, None, {}, label=label)
            before = request(5_000_000_099, 6_000_000_000)
            self.assertEqual(audit.request_owners(before, {"one": current}),
                             [label] if label.startswith("held_") else [])
            self.assertEqual(audit.request_owners(request(5_000_000_100, 6_000_000_000), {"one": current}), [])

    def test_page_index_uses_receive_order_without_changing_trace_order(self):
        first = {"request": request(150, 500)}
        second = {"request": {**request(250, 300), "request_serial": 2}}
        objects = {2: second, 1: first}
        before = copy.deepcopy(objects)
        indexed = audit.ObjectHistory(objects)
        current = call(100, 200, None, {})
        self.assertEqual(audit.observed_requests(indexed, current), [first])
        self.assertEqual(audit.observed_requests(objects, current), [first])
        self.assertEqual(audit.page_requests(indexed, current), [first])
        self.assertEqual(objects, before)
        logged = [{**second["request"], "schema": 1, "sequence": 1},
                  {**first["request"], "schema": 1, "sequence": 2}]
        audit.numbered(logged)

    def test_late_log_is_counted_in_the_original_page_budget(self):
        evidence, _, scan, _, final = zero_progress_fixture(operation="GET")
        final["request"]["monotonic_ns"] = 4_110_000_000
        budget = audit.page_budget(audit.ObjectHistory(evidence.objects), scan[0])
        self.assertEqual(budget["exact_gets"], 1)
        self.assertEqual(budget["unconsumed_final_get"], final["request"]["request_serial"])
        self.assertEqual(budget["metadata_options"], {65536})
        audit.no_post_return_work(evidence.objects, scan[0], scan[1])

    def test_real_post_return_receive_is_still_rejected(self):
        current = call(100, 200, None, {}, label="original")
        following = call(400, 500, None, {}, label="next")
        original = request(150, 300)
        audit.no_post_return_work({1: {"request": original}}, current, following)
        changed = copy.deepcopy(original)
        audit.control_retime_event(changed, 220)
        self.assertEqual(changed["request_received_monotonic_ns"], 220)
        self.assertEqual(changed["monotonic_ns"], 220)
        self.assertEqual(audit.request_owners(changed, {"one": current, "next": following}), [])
        with self.assertRaisesRegex(ValueError, "after its original HTTP response"):
            audit.no_post_return_work({1: {"request": changed}}, current, following)
        self.assertEqual(original, request(150, 300))

    def test_clock_mutations_reach_their_specific_boundaries_without_modifying_the_original(self):
        original = {"discovery-s3.jsonl": [request()]}
        for kind, boundary in (("missing", "missing its original receipt clock"),
                               ("invalid", "invalid receipt clock"),
                               ("after_log", "follows its authenticated request log")):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(original)
                audit.control_receipt_clock(changed, kind)
                with self.assertRaisesRegex(ValueError, boundary):
                    audit.received(changed["discovery-s3.jsonl"][0])
        self.assertEqual(original, {"discovery-s3.jsonl": [request()]})

    def test_counterfactual_time_shift_keeps_both_original_observation_boundaries(self):
        before = request(100, 160)
        after = request(170, 180)
        data = {"discovery-s3.jsonl": [before, after]}
        audit.control_shift_after(data, 150, 1000)
        self.assertEqual((audit.received(before), audit.stamp(before)), (100, 1160))
        self.assertEqual((audit.received(after), audit.stamp(after)), (1170, 1180))
        legacy = request()
        del legacy["request_received_monotonic_ns"]
        with self.assertRaisesRegex(ValueError, "missing its original receipt clock"):
            audit.control_retime_event(legacy, 500)


def signed_headers(method, path, payload, backend):
    """Known unit-only credentials; exercise the fixture's real SigV4 verifier."""
    digest = hashlib.sha256(payload).hexdigest()
    date, scope = "20261113T000000Z", "20261113/us-east-1/s3/aws4_request"
    headers = http.client.HTTPMessage()
    for name, value in (("Host", "unit.invalid"), ("Content-Length", str(len(payload))),
                        ("x-amz-date", date), ("x-amz-content-sha256", digest)):
        headers[name] = value
    names = "host;x-amz-content-sha256;x-amz-date"
    canonical = "\n".join((method, path, "", "".join(name + ":" + headers[name] + "\n" for name in names.split(";")), names, digest))
    message = "\n".join(("AWS4-HMAC-SHA256", date, scope, hashlib.sha256(canonical.encode()).hexdigest()))
    key = ("AWS4" + backend.secret).encode()
    for value in scope.split("/"):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={backend.access}/{scope}, SignedHeaders={names}, Signature={signature}"
    return headers


class HandlerEntryClockTests(unittest.TestCase):
    def dispatch(self, directory, method, *, invalid=False):
        backend = SimpleNamespace(access="unit-access", secret="unit-secret", port=123)
        handlers, observed = [], {}

        def make_server(_address, handler):
            handlers.append(handler)
            return SimpleNamespace(server_port=456, serve_forever=lambda: None)

        with patch.object(proxy.http.server, "ThreadingHTTPServer", side_effect=make_server), \
                patch.object(proxy.threading, "Thread", return_value=Mock()):
            owner = proxy.Proxy(backend, directory)
        handler = object.__new__(handlers[0])
        handler.command = method
        handler.path = "/scap-test/scap-object/v1/1/7/clock"
        payload = b"unit-body" if method == "PUT" else b""
        handler.headers = signed_headers(method, handler.path, payload, backend)
        if invalid:
            handler.headers.replace_header("Authorization", "invalid")
        handler.connection = SimpleNamespace(settimeout=lambda _seconds: observed.setdefault("settimeout", time.monotonic_ns()))

        class Input(io.BytesIO):
            def read(self, size):
                observed["body_read"] = time.monotonic_ns()
                return super().read(size)

        handler.rfile, handler.wfile = Input(payload), io.BytesIO()
        handler.send_response_only = lambda _status: None
        handler.send_header = lambda _name, _value: None
        handler.end_headers = lambda: None
        response = SimpleNamespace(status=200, read=lambda _limit: b"unit-result",
                                   getheader=lambda _name: '"unit-etag"', getheaders=lambda: [])
        connection = Mock()
        connection.getresponse.return_value = response
        original_signing = proxy.signing

        def signing(*args):
            observed["signing"] = time.monotonic_ns()
            return original_signing(*args)

        before = time.monotonic_ns()
        with patch.object(proxy, "signing", side_effect=signing), \
                patch.object(proxy.http.client, "HTTPConnection", return_value=connection) as upstream:
            getattr(handler, "do_" + method)()
        events = [json.loads(line) for line in (directory / "discovery-s3.jsonl").read_text().splitlines()]
        return owner, events, observed, before, payload, upstream.call_count

    def test_same_authenticated_get_and_put_keep_the_actual_entry_clock(self):
        for method in ("GET", "PUT"):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as temporary:
                owner, events, observed, before, payload, forwarded = self.dispatch(Path(temporary), method)
                self.assertEqual(owner.errors, [])
                current = next(row for row in events if row["event"] == "request")
                clock = audit.received(current)
                self.assertLessEqual(before, clock)
                for name in ("settimeout", "body_read", "signing"):
                    self.assertLessEqual(clock, observed[name])
                self.assertLess(observed["signing"], audit.stamp(current))
                self.assertEqual(current["method"], method)
                self.assertEqual(current["key"], "scap-object/v1/1/7/clock")
                self.assertEqual(current["request"], proxy.body(payload))
                self.assertTrue(current["signing"]["verified"])
                self.assertEqual({row["request_serial"] for row in events}, {1})
                self.assertTrue(all("request_received_monotonic_ns" not in row for row in events if row is not current))
                self.assertEqual(forwarded, 1)
                audit.numbered(events)

    def test_failed_authentication_cannot_publish_a_request_witness(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner, events, _, _, _, forwarded = self.dispatch(Path(temporary), "GET", invalid=True)
            self.assertEqual(len(owner.errors), 1)
            self.assertEqual([row["event"] for row in events], ["fixture_failed"])
            self.assertEqual(forwarded, 0)


if __name__ == "__main__":
    unittest.main()
