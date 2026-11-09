#!/usr/bin/env python3
"""Recompute transport checks from raw HTTP bytes and owned-child observations."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path


PROFILE = {"version": 1, "max_connections": 2, "max_headers": 4,
           "max_header_bytes": 512, "max_buffer_bytes": 8192, "header_timeout_ms": 3000}
CASES = {"capacity", "first_header_deadline", "keepalive_header_deadline",
         "header_bytes_at", "header_bytes_over", "header_count_at", "header_count_over", "h2"}
H2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def raw(value):
    return base64.b64decode(value, validate=True)


def status(response):
    line = response.split(b"\r\n", 1)[0].split(b" ")
    if len(line) < 2 or line[0] != b"HTTP/1.1":
        raise ValueError("not an HTTP/1.1 response")
    return int(line[1])


def healthy(response):
    assert status(response) == 200
    head, body = response.split(b"\r\n\r\n", 1)
    lengths = [int(line.split(b":", 1)[1]) for line in head.split(b"\r\n")[1:]
               if line.lower().startswith(b"content-length:")]
    assert lengths == [len(body)]
    assert json.loads(body) == {"status": "alive", "protocol": 1}


def verify(observations):
    assert observations["schema"] == 1
    assert observations["profile"] == PROFILE
    rows = observations["cases"]
    assert len(rows) == len(CASES)
    assert {row["case"] for row in rows} == CASES
    by_name = {row["case"]: row for row in rows}
    capacity = by_name["capacity"]
    for occupied in capacity["occupied"]:
        assert raw(occupied["request"]) == b"GET /healthz HTTP/1.1\r\nHost: unit\r\n\r\n"
        healthy(raw(occupied["response"]))
        assert raw(occupied["partial_request"]) == b"GET /healthz HTTP/1.1\r\nHost:"
        assert occupied["hold_ns"] <= capacity["probe_start_ns"]
        assert capacity["release_ns"] - occupied["hold_ns"] < 1_000_000_000
    assert len(capacity["occupied"]) == PROFILE["max_connections"]
    assert raw(capacity["request"]) == b"GET /healthz HTTP/1.1\r\nHost: unit\r\nConnection: close\r\n\r\n"
    assert raw(capacity["probe_response"]) == b""
    assert capacity["probe_outcome"] == "timeout"
    assert capacity["probe_end_ns"] - capacity["probe_start_ns"] >= 150_000_000
    assert capacity["release_ns"] >= capacity["probe_end_ns"]
    assert capacity["response_ns"] >= capacity["release_ns"]
    healthy(raw(capacity["response"]))
    for name in ("first_header_deadline", "keepalive_header_deadline"):
        row = by_name[name]
        assert raw(row["request"]) == b"GET /healthz HTTP/1.1\r\nHost:"
        assert raw(row["drip"]) == b" unit"
        assert raw(row["probe_response"]) == b""
        assert row["probe_outcome"] == "timeout"
        assert row["drip_ns"] - row["start_ns"] >= 1_900_000_000
        elapsed = row["close_ns"] - row["start_ns"]
        assert 2_400_000_000 <= elapsed <= 4_500_000_000
        assert row["closed"] is True
        response = raw(row["response"])
        assert not response or status(response) == 408
        if name == "keepalive_header_deadline":
            healthy(raw(row["first_response"]))
    for name, expected, header_size, count in (
        ("header_bytes_at", 200, 512, None),
        ("header_bytes_over", 431, 513, None),
        ("header_count_at", 200, None, 4),
        ("header_count_over", 431, None, 5),
    ):
        row = by_name[name]
        request = raw(row["request"])
        assert request.endswith(b"\r\n\r\n")
        if header_size is not None:
            assert len(request) == header_size
        if count is not None:
            assert len(request[:-4].split(b"\r\n")) - 1 == count
        assert row["closed"] is True
        response = raw(row["response"])
        assert status(response) == expected
        if expected == 200:
            healthy(response)
    h2 = by_name["h2"]
    assert raw(h2["request"]) == H2
    assert h2["closed"] is True
    response = raw(h2["response"])
    assert not response or status(response) == 400
    cleanup = observations["cleanup"]
    assert cleanup["returncode"] == 0
    assert cleanup["identity"]["pid_source"] == "owned_Popen_child"
    assert cleanup["usage"]["available"] is True
    assert cleanup["usage"]["source"] == "kernel_wait4_owned_child"
    assert cleanup["idle_closed"] is True
    assert cleanup["reaped_ns"] >= cleanup["signal_ns"]
    assert cleanup["reaped_ns"] - cleanup["signal_ns"] < 6_000_000_000
    return sorted(CASES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observations", type=Path)
    args = parser.parse_args()
    result = verify(json.loads(args.observations.read_text()))
    print(json.dumps({"verified": result, "owned_child_cleanup": True}, sort_keys=True))


if __name__ == "__main__":
    main()
