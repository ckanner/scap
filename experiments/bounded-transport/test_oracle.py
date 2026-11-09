"""Negative controls for the raw-observation oracle; no daemon is run here."""
import base64
import copy
import unittest

from oracle import CASES, H2, PROFILE, verify


def enc(value):
    return base64.b64encode(value).decode()


def fixture():
    body = b'{"status":"alive","protocol":1}'
    healthy = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    rows = [{"case": "capacity", "occupied": [{
                 "request": enc(b"GET /healthz HTTP/1.1\r\nHost: unit\r\n\r\n"),
                 "response": enc(healthy), "partial_request": enc(b"GET /healthz HTTP/1.1\r\nHost:"),
                 "hold_ns": 0}] * 2,
             "request": enc(b"GET /healthz HTTP/1.1\r\nHost: unit\r\nConnection: close\r\n\r\n"),
             "probe_response": "", "probe_outcome": "timeout", "probe_start_ns": 0,
             "probe_end_ns": 200_000_000, "release_ns": 200_000_001,
             "response_ns": 210_000_000, "response": enc(healthy)}]
    for name in ("first_header_deadline", "keepalive_header_deadline"):
        rows.append({"case": name, "request": enc(b"GET /healthz HTTP/1.1\r\nHost:"),
                     "drip": enc(b" unit"), "probe_response": "", "probe_outcome": "timeout",
                     "start_ns": 0, "drip_ns": 2_000_000_000, "close_ns": 3_000_000_000,
                     "closed": True, "response": "", "first_response": enc(healthy)})
    prefix = b"GET /healthz HTTP/1.1\r\nHost: unit\r\nConnection: close\r\nX: "
    for name, size in (("header_bytes_at", 512), ("header_bytes_over", 513)):
        rows.append({"case": name, "request": enc(prefix + b"x" * (size - len(prefix) - 4) + b"\r\n\r\n"),
                     "closed": True, "response": enc(healthy if size == 512 else b"HTTP/1.1 431 Too Large\r\n\r\n")})
    for name, count in (("header_count_at", 4), ("header_count_over", 5)):
        rows.append({"case": name, "request": enc(b"GET /healthz HTTP/1.1\r\n" + b"X: y\r\n" * count + b"\r\n"),
                     "closed": True, "response": enc(healthy if count == 4 else b"HTTP/1.1 431 Too Large\r\n\r\n")})
    rows.append({"case": "h2", "request": enc(H2), "response": "", "closed": True})
    return {"schema": 1, "profile": copy.deepcopy(PROFILE), "cases": rows,
            "cleanup": {"returncode": 0, "identity": {"pid_source": "owned_Popen_child"},
                        "usage": {"available": True, "source": "kernel_wait4_owned_child"},
                        "idle_closed": True, "signal_ns": 0, "reaped_ns": 1}}


class OracleTests(unittest.TestCase):
    def test_complete_observations_are_recomputed(self):
        self.assertEqual(verify(fixture()), sorted(CASES))

    def test_missing_duplicate_and_wrong_profile_fail(self):
        for mutation in (lambda d: d["cases"].pop(),
                         lambda d: d["cases"].append(d["cases"][0]),
                         lambda d: d["profile"].update(max_connections=3)):
            value = fixture()
            mutation(value)
            with self.assertRaises(AssertionError):
                verify(value)

    def test_behaviour_negative_controls_fail(self):
        changes = [("capacity", "probe_outcome", "received"),
                   ("capacity", "probe_response", enc(b"HTTP/1.1 200")),
                   ("first_header_deadline", "close_ns", 5_000_000_000),
                   ("keepalive_header_deadline", "close_ns", 5_000_000_000),
                   ("header_bytes_over", "response", fixture()["cases"][0]["response"]),
                   ("header_count_over", "response", fixture()["cases"][0]["response"]),
                   ("h2", "closed", False), ("h2", "response", enc(b"\0" * 9))]
        for name, field, replacement in changes:
            value = fixture()
            next(row for row in value["cases"] if row["case"] == name)[field] = replacement
            with self.subTest(name=name, field=field), self.assertRaises((AssertionError, ValueError)):
                verify(value)

    def test_unreaped_or_forced_child_exit_is_not_cleanup_success(self):
        for replacement in ({"returncode": -9}, {"usage": {"available": False}}, {"idle_closed": False}):
            value = fixture()
            value["cleanup"].update(replacement)
            with self.assertRaises(AssertionError):
                verify(value)

    def test_capacity_must_be_released_before_the_header_deadline(self):
        value = fixture()
        value["cases"][0].update(release_ns=3_000_000_000, response_ns=3_100_000_000)
        with self.assertRaises(AssertionError):
            verify(value)


if __name__ == "__main__":
    unittest.main()
