"""Real HTTP proxy instrumentation tests; not a real S3 or database acceptance."""
import contextlib
import hashlib
import http.client
import http.server
import json
import io
from pathlib import Path
import tempfile
import threading
import unittest

import run as support


class CatalogueCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.evidence = Path(self.temporary.name)
        captured = contextlib.redirect_stdout(io.StringIO())
        captured.__enter__()
        self.addCleanup(captured.__exit__, None, None, None)
        self.body = b'{"format":1,"operation":18446744073709551615}'
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args): pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(owner.body)))
                self.send_header("ETag", '"exact-etag"')
                self.end_headers()
                self.wfile.write(owner.body)

            def do_PUT(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.send_header("ETag", '"new-etag"')
                self.end_headers()

        self.backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.thread.start()
        self.proxy = support.Proxy(self.backend.server_port, self.evidence)
        self.proxy.capture = True
        self.addCleanup(self.close)

    def close(self):
        self.proxy.close()
        self.backend.shutdown()
        self.backend.server_close()
        self.thread.join(3)

    def call(self, method, body=None, path="/scap-test/scap-object/v1/1/1/catalogue/v1/name/abc"):
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.server.server_port, timeout=2)
        try:
            connection.request(method, path, body, {"If-None-Match": "*", "Authorization": "synthetic-not-recorded"})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def history(self):
        return [json.loads(line) for line in (self.evidence / "history.jsonl").read_text().splitlines()]

    def test_opt_in_preserves_complete_bounded_json_and_no_authorization_header(self):
        self.proxy.capture_catalogue = True
        self.assertEqual(self.call("PUT", self.body), (200, b""))
        self.assertEqual(self.call("GET"), (200, self.body))
        events = self.history()
        put = next(e for e in events if e["event"] == "object_request" and e["method"] == "PUT")
        get = next(e for e in events if e["event"] == "object_response" and e["method"] == "GET")
        self.assertEqual(bytes(put["catalogue_request_bytes"]), self.body)
        self.assertEqual(bytes(get["catalogue_response_bytes"]), self.body)
        self.assertEqual(put["request_sha256"], hashlib.sha256(self.body).hexdigest())
        self.assertEqual(get["response_sha256"], hashlib.sha256(self.body).hexdigest())
        self.assertEqual(put["request_bytes"], len(self.body))
        self.assertEqual(get["response_bytes"], len(self.body))
        self.assertEqual(put["if_none_match"], "*")
        self.assertEqual(get["etag"], '"exact-etag"')
        self.assertNotIn("synthetic-not-recorded", json.dumps(events))
        self.assertEqual(self.proxy.errors, [])

    def test_default_and_non_catalogue_paths_do_not_gain_metadata_capture(self):
        self.call("GET")
        self.proxy.capture_catalogue = True
        self.call("GET", path="/scap-test/scap-object/v1/1/1/1/head")
        events = self.history()
        gets = [e for e in events if e["event"] == "object_response"]
        self.assertEqual(len(gets), 2)
        self.assertTrue(all("catalogue_response_bytes" not in e for e in gets))
        self.assertEqual(bytes(gets[1]["head_response_bytes"]), self.body)

    def test_oversized_capture_fails_instead_of_truncating_or_producing_a_response(self):
        self.proxy.capture_catalogue = True
        self.body = b"x" * (65536 + 1)
        for method in ("PUT", "GET"):
            with self.subTest(method=method), self.assertRaises(http.client.RemoteDisconnected):
                self.call(method, self.body if method == "PUT" else None)
        self.assertEqual(len(self.proxy.errors), 2)
        failures = [e for e in self.history() if e["event"] == "transport_fixture_failed"]
        self.assertEqual(len(failures), 2)
        self.assertTrue(all("64 KiB" in e["error"] for e in failures))
        self.assertFalse(any(e["event"] == "object_response" for e in self.history()))


if __name__ == "__main__": unittest.main()
