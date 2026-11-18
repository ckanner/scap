"""Small synthetic rule tests; never masquerade as actual HTTP/S3 acceptance."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import struct
import tempfile
import unittest

import controls
import oracle


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def base_head(name):
    return {"format": 6, "scope": {key: int(value) for key, value in oracle.SCOPES[name].items()},
            "head_serial": 4, "storage": {"active_generation": 1, "allocated_through": 1, "plan": None, "sweep": None},
            "revision": 4, "transition": {"revision": 4, "nonce": 10002 + 10 * oracle.NAMES.index(name)},
            "sequence": 1, "owner_epoch": 1, "owner_instance": 8101, "active": True, "auth_epoch": 2,
            "policy": oracle.native_policy(oracle.BASE_POLICY), "lifecycle": "ready", "creation": None, "deletion": None,
            "data_root": "a" * 64, "quota": {"max_bytes": 10737418240},
            "retention": {"max_entries": 4096, "max_result_bytes": 268435456}, "request_epoch": 1,
            "windows": [{"epoch": 1, "root": "b" * 64, "count": 1, "result_bytes": 80}]}


def object_frame(name="success", *, spacing=False):
    metadata = {"format": 2, "scope": {key: int(value) for key, value in oracle.SCOPES[name].items()},
                "payload": {"kind": "manifest", "value": {"page_count": 0, "root": None}}}
    raw = json.dumps(metadata, indent=2).encode() if spacing else encoded(metadata)
    frame = b"SCAPOBJ2" + struct.pack("<IQ", len(raw), 0) + raw
    return oracle.object_prefix(name) + oracle.sha(frame), frame


def exchange(serial, name, method, request_raw=b"", response_raw=b"", *, status=200, if_match=None, etag=None, worker="M", path=None):
    stamp = 1000 + serial * 20
    common = {"request_serial": serial, "listener_id": "s3-" + worker, "handler_id": "s3-" + worker + ":" + str(serial),
              "worker": worker, "method": method, "path": path or oracle.head_path(name), **oracle.pack(request_raw, "request_body"),
              "if_match": if_match, "if_none_match": "*" if method == "PUT" and if_match is None else None,
              "signing": {"payload_sha256": oracle.sha(request_raw)}}
    value = {"source": {"file": "s3.jsonl", "request_serial": serial, "handler_id": common["handler_id"],
                         "sequences": [serial * 4 + index for index in range(4)]}}
    for index, (field, event) in enumerate(zip(("request", "forwarded", "response", "terminal"),
                                              ("object_request", "object_forwarded", "object_response", "object_response_delivered"))):
        row = {"schema": 1, "sequence": serial * 4 + index, "monotonic_ns": stamp + index, "event": event, **deepcopy(common)}
        if index >= 2:
            row.update(status=status, etag=etag or '"' + oracle.sha(response_raw if method == "GET" else request_raw) + '"',
                       response_origin="backend", **oracle.pack(response_raw, "response_body"))
        value[field] = row
    return value


def projection_fixture():
    bases = {}
    for name in oracle.NAMES:
        raw = encoded(base_head(name))
        bases[name] = {**oracle.pack(raw), "etag": '"' + oracle.sha(raw) + '"', "source": {"file": "synthetic", "scope": name}}
    success5 = oracle.advance(base_head("success"), 20001, owner_epoch=2, owner_instance=8202, active=False)
    success6 = oracle.advance(success5, 20002, auth_epoch=3, policy=oracle.native_policy(oracle.NEXT_POLICY))
    unknown5 = oracle.advance(base_head("put_unknown"), 22001, auth_epoch=3, policy=oracle.native_policy(oracle.NEXT_POLICY))
    stale5 = oracle.advance(base_head("stale_412"), 23001, owner_epoch=2, owner_instance=8202, active=False)
    competitor5 = oracle.advance(base_head("stale_412"), 23002, auth_epoch=3, policy=oracle.native_policy(oracle.NEXT_POLICY))
    takeover = {**oracle.pack(encoded(success5)), "etag": '"' + oracle.sha(encoded(success5)) + '"', "source": {"file": "synthetic"}}
    stream = []
    def get(name, value=None, raw=None):
        value = value or base_head(name)
        raw = encoded(value) if raw is None else raw
        stream.append(exchange(len(stream) + 1, name, "GET", response_raw=raw))
    def put(name, value, status=200, previous=None):
        stream.append(exchange(len(stream) + 1, name, "PUT", encoded(value), status=status,
                               if_match=(previous or bases[name])["etag"]))
    get("success"); get("success"); put("success", success5)
    get("success", success5); put("success", success6, previous=takeover); get("success", success6)
    get("get_unknown"); get("put_unknown"); put("put_unknown", unknown5)
    get("stale_412"); put("stale_412", stale5, status=412)
    get("permission"); get("permission")
    get("known_quarantine", raw=b"{}"); get("known_quarantine"); get("known_quarantine"); get("known_quarantine")
    calls = []
    credentials = {"writer": "1" * 64, "manager": "2" * 64, "reader": "3" * 64}
    for spec in oracle.COMMANDS:
        if spec["worker"] != "M":
            continue
        ok = spec["http_status"] == 200
        outcome = {"ok": True, "value": oracle.status_from_head(base_head(spec["scope"]))} if ok else {
            "ok": False, "error": {"name": "UnknownError" if oracle.expected_code(spec["id"]) == "UNKNOWN" else "RemoteError", "code": oracle.expected_code(spec["id"])}}
        calls.append({"command": spec["id"], "request_body": oracle.action(spec), "status": spec["http_status"],
                      "credential_sha256": credentials[spec["caller"]], "outcome": outcome,
                      "source": {"ledger": "synthetic", "call_id": spec["id"]}})
    path, raw = object_frame()
    return {"schema": 1, "calls": calls, "stream": stream, "bases": bases, "success_takeover": takeover,
            "competitor": exchange(30, "stale_412", "PUT", encoded(competitor5), if_match=bases["stale_412"]["etag"], worker="S"),
            "credentials": credentials, "last_http_response_ns": 2000,
            "lifetime": {"service_start_ns": 500, "service_wait4_ns": 3000, "proxy_join_ns": 4000, "event_sequences": [1, 100, 101]},
            "immutable_samples": [exchange(40, "success", "GET", response_raw=raw, worker="S", path=path),
                                  exchange(41, "success", "PUT", request_raw=raw, worker="S", path=path)]}


def startup_fixture():
    config = {'backend': {'access_key_sha256': 'a' * 64},
              's3_endpoints': {'S': 'http://127.0.0.1:10001', 'M': 'http://127.0.0.1:10002'}}
    events, items = [], []
    for worker, spawn, observed, ready in (('S', 900, 1000, 1050), ('M', 1050, 1090, 1100)):
        child = {'pid': int(oracle.WORKERS[worker]), 'pid_source': 'owned_Popen_child', 'spawn_monotonic_ns': observed}
        events.extend([{'event': 'service_started', 'worker': worker, 'identity': child,
                        'spawn_requested_ns': spawn, 'monotonic_ns': observed + 1},
                       {'event': 'service_ready', 'worker': worker, 'identity': child, 'monotonic_ns': ready}])
        value = b'SCAP-WORKER-INSTANCE-v1\0' + int(oracle.WORKERS[worker]).to_bytes(8, 'big')
        path = '/scap-test/scap-worker/v1/instances/' + oracle.WORKERS[worker]
        items.append(exchange(len(items) + 1, 'success', 'PUT', request_raw=value, worker=worker, path=path))
        items.append(exchange(len(items) + 1, 'success', 'GET', response_raw=value, worker=worker, path=path))
    items.append(exchange(5, 'success', 'GET', response_raw=encoded(base_head('success')), worker='M'))
    trace, counters = [], {}
    for item in items:
        worker = item['request']['worker']
        counters[worker] = counters.get(worker, 0) + 1
        handler = 's3-' + worker + ':' + str(counters[worker])
        for key in ('request', 'forwarded', 'response', 'terminal'):
            row = item[key]
            row['handler_id'] = handler
            row['signing'].update(algorithm='AWS4-HMAC-SHA256', access_key_sha256='a' * 64,
                credential_scope='20261118/us-east-1/s3/aws4_request', signature_sha256='b' * 64,
                host=oracle.endpoint(config['s3_endpoints'][worker]), date='20261118T000000Z',
                signed_headers=['host', 'x-amz-content-sha256', 'x-amz-date'])
        common = {'schema': 1, 'listener_id': 's3-' + worker, 'handler_id': handler, 'worker': worker, 'channel': 's3'}
        trace.append({**common, 'event': 'handler_started', 'monotonic_ns': oracle.stamp(item['request']) - 1})
        trace.extend(item[key] for key in ('request', 'forwarded', 'response', 'terminal'))
        trace.append({**common, 'event': 'handler_finished', 'monotonic_ns': oracle.stamp(item['terminal']) + 1, 'failed': False})
    for number, row in enumerate(trace, 1):
        row['sequence'] = number
    return trace, config, events


class StartupOracleTests(unittest.TestCase):
    def test_private_identity_accepts_original_evidence_parent_on_any_mount(self):
        for parent in ('/tmp', '/home/runner/work/_temp', '/workspace/scratch/evidence'):
            with self.subTest(parent=parent):
                oracle.private_runtime_identity({'path': parent + '/scap-metadata-private-ab_123',
                                                 'device': 27, 'inode': 12345})

    def test_private_identity_rejects_aliases_wrong_owner_shape_and_invalid_inode(self):
        valid = {'path': '/workspace/scap-metadata-private-owned', 'device': 27, 'inode': 12345}
        changed = [dict(valid, path=path) for path in ('scap-metadata-private-owned',
            '/workspace/../scap-metadata-private-owned', '/workspace//scap-metadata-private-owned',
            '/workspace/./scap-metadata-private-owned', '/workspace/unowned', '/workspace/scap-metadata-private-')]
        changed += [dict(valid, inode=0), dict(valid, device=True), dict(valid, extra=1)]
        for value in changed:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'private runtime identity changed'):
                oracle.private_runtime_identity(value)

    def test_filters_only_four_proven_claims_and_keeps_all_handlers(self):
        trace, config, events = startup_fixture()
        exchanges, handlers, startup = oracle.s3_exchanges(trace, config, events)
        self.assertEqual((len(exchanges), len(handlers)), (1, 5))
        self.assertEqual(exchanges[0]['request']['path'], oracle.head_path('success'))
        self.assertEqual(startup, {'instances': {'S': '8101', 'M': '8202'}, 'requests': 4, 'physical_requests': 5})

    def test_six_raw_controls_reach_the_exact_startup_rule(self):
        trace, config, events = startup_fixture()
        for case, rule in controls.STARTUP_CASES.items():
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, '^' + rule + '$'):
                oracle.s3_exchanges(controls.startup_mutated(trace, events, case), config, events)
        self.assertEqual(len(oracle.s3_exchanges(trace, config, events)[0]), 1)

    def test_prefix_is_not_an_unverified_namespace_exemption(self):
        trace, config, events = startup_fixture()
        for row in trace:
            if row.get('path', '').endswith('/instances/8101'):
                row['path'] = '/scap-test/scap-worker/v1/instances/9999'
        with self.assertRaisesRegex(ValueError, 'S3 request escaped exact Scope/physical generation'):
            oracle.s3_exchanges(trace, config, events)

    def test_readiness_must_belong_to_the_same_owned_process(self):
        trace, config, events = startup_fixture()
        events[1]['identity'] = {**events[1]['identity'], 'pid': 9999}
        with self.assertRaisesRegex(ValueError, 'worker-identity-owned-ready'):
            oracle.s3_exchanges(trace, config, events)

    def test_hidden_startup_cannot_share_the_two_claims(self):
        trace, config, events = startup_fixture()
        events.append(deepcopy(events[0]))
        with self.assertRaisesRegex(ValueError, 'worker-identity-lifecycle-denominator'):
            oracle.s3_exchanges(trace, config, events)

    def test_callback_after_ready_keeps_original_response_order(self):
        trace, config, events = startup_fixture()
        for row in trace:
            if row['handler_id'] == 's3-S:2' and row['event'] in ('object_response_delivered', 'handler_finished'):
                row['monotonic_ns'] += 20
        trace.sort(key=oracle.stamp)
        oracle.s3_exchanges(trace, config, events)


def number_observer(trace, calls):
    """Keep mutations causal-looking; the oracle must reject the actual rule."""
    for number, row in enumerate(trace, 1):
        row["sequence"], row["monotonic_ns"] = number, str(number * 100)
    for call in calls.values():
        selected = [row for row in trace if row.get("call_id") == call["request"]["call_id"]]
        first = next(row for row in selected if row["event"] == "fetch_started")
        call["request"]["monotonic_ns"] = str(int(first["monotonic_ns"]) - 10)
        body = next((row for row in selected if row["event"] == "fetch_body_complete"), None)
        if body is not None:
            call["response"]["monotonic_ns"] = str(int(body["monotonic_ns"]) + 10)


def observer_fixture(*schedules):
    """A complete original Fetch plus only the recorder's visible socket prefix."""
    trace = [{"schema": 1, "phase": "metadata", "event": "observer_started",
              "limits": {"callEvents": 64, "callRequests": 8, "callConnections": 8, "connectionEvents": 16,
                         "activeConnections": 128, "pendingEvents": 1024}}]
    calls, remaining = {}, 0
    for index, schedule in enumerate(schedules, 1):
        call_id, connection = "metadata:42:" + str(index), "42:connection:" + str(index)
        request_id = call_id + ":request:1"
        info = not schedule.startswith("clean")
        closed = not schedule.endswith("open")
        remaining += not closed
        def emit(event):
            row = {"schema": 1, "phase": "metadata", "event": event}
            row["connection_id" if event.startswith("socket_") else "call_id"] = connection if event.startswith("socket_") else call_id
            if event in ("request_created", "request_send_headers", "request_response_headers", "request_body_complete"):
                row["request_id"] = request_id
            if event == "request_send_headers":
                row["connection_id"] = connection
            if event in ("request_response_headers", "fetch_response_headers"):
                row["status"] = 200
            if event == "socket_error":
                row.update(error_name="UNKNOWN", error_code="UND_ERR_INFO", cause_code="UNKNOWN")
            if event == "socket_close":
                row["had_error"] = info
            if event == "call_observation_finished":
                row.update(outcome="response", stage="evidence", observation_status="RECORDED",
                           request_identity="OBSERVED", connection_identity="OBSERVED",
                           request_ids=[request_id], connection_ids=[connection])
            trace.append(row)
        for event in ("fetch_started", "request_created", "socket_observed", "request_send_headers", "request_response_headers"):
            emit(event)
        if schedule == "streaming":
            emit("fetch_response_headers"); emit("fetch_body_started")
        emit("request_body_complete")
        if info:
            emit("socket_error")
        if schedule == "close_before_fetch":
            emit("socket_close")
        if schedule != "streaming":
            emit("fetch_response_headers"); emit("fetch_body_started")
        emit("fetch_body_complete"); emit("call_observation_finished")
        if closed and schedule != "close_before_fetch":
            emit("socket_close")
        raw = b'{"ok":true}'
        calls[str(index)] = {"request": {"call_id": call_id},
                            "response": {"call_id": call_id, "status": 200, "body": base64.b64encode(raw).decode(), "body_sha256": oracle.sha(raw)},
                            "response_body": raw}
    trace.append({"schema": 1, "phase": "metadata", "event": "observer_stopped", "observation_status": "RECORDED",
                  "remaining_connections": remaining})
    number_observer(trace, calls)
    return trace, calls


class ObserverTests(unittest.TestCase):
    def audit(self, trace, calls):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "http-client-transport.jsonl").write_text("".join(json.dumps(row) + "\n" for row in trace))
            return oracle.observer_proof(directory, calls)

    def test_complete_info_and_graceful_prefixes_allow_both_fetch_schedules(self):
        for schedule in ("after_fetch", "close_before_fetch", "streaming", "info_open", "clean_closed", "clean_open"):
            with self.subTest(schedule=schedule):
                trace, calls = observer_fixture(schedule)
                result = self.audit(trace, calls)
                self.assertEqual(result["informational_disposals"], int(not schedule.startswith("clean")))
                self.assertEqual(result["remaining_connections"], int(schedule.endswith("open")))
                self.assertEqual(result["observed_closed_connections"], int(not schedule.endswith("open")))
                self.assertEqual(result["observation_status"], "RECORDED")

    def test_info_before_its_request_body_completion_is_rejected(self):
        trace, calls = observer_fixture("after_fetch")
        error = next(row for row in trace if row["event"] == "socket_error")
        trace.remove(error)
        trace.insert(next(index for index, row in enumerate(trace) if row["event"] == "request_body_complete"), error)
        number_observer(trace, calls)
        with self.assertRaisesRegex(ValueError, "preceded its original request body completion"):
            self.audit(trace, calls)

    def test_socket_end_must_follow_send_and_can_precede_close(self):
        trace, calls = observer_fixture("after_fetch")
        end = {"schema": 1, "phase": "metadata", "event": "socket_end", "connection_id": "42:connection:1"}
        trace.insert(next(index for index, row in enumerate(trace) if row["event"] == "socket_close"), end)
        number_observer(trace, calls)
        self.assertEqual(self.audit(trace, calls)["observed_closed_connections"], 1)

        trace.remove(end)
        trace.insert(next(index for index, row in enumerate(trace) if row["event"] == "request_send_headers"), end)
        number_observer(trace, calls)
        with self.assertRaisesRegex(ValueError, "socket event preceded original request binding"):
            self.audit(trace, calls)

    def test_info_cannot_borrow_another_connections_completed_body(self):
        trace, calls = observer_fixture("after_fetch", "after_fetch")
        errors = [row for row in trace if row["event"] == "socket_error"]
        second_observed = next(row for row in trace if row["event"] == "socket_observed" and row["connection_id"] == "42:connection:2")
        trace.remove(second_observed)
        trace.insert(trace.index(errors[0]), second_observed)
        errors[0]["connection_id"] = "42:connection:2"
        trace.remove(errors[1])
        next(row for row in trace if row["event"] == "socket_close" and row["connection_id"] == "42:connection:1")["had_error"] = False
        number_observer(trace, calls)
        with self.assertRaisesRegex(ValueError, "preceded its original request body completion"):
            self.audit(trace, calls)

    def test_connection_cannot_cover_two_complete_original_calls(self):
        trace, calls = observer_fixture("after_fetch", "after_fetch")
        for row in trace:
            if row.get("call_id") == "metadata:42:2":
                if row["event"] == "request_send_headers":
                    row["connection_id"] = "42:connection:1"
                if row["event"] == "call_observation_finished":
                    row["connection_ids"] = ["42:connection:1"]
        with self.assertRaisesRegex(ValueError, "shared by multiple original requests"):
            self.audit(trace, calls)

    def test_only_the_pinned_informational_safe_fields_are_accepted(self):
        for key, value in (("error_code", "ECONNRESET"), ("error_code", "UNKNOWN"),
                           ("error_name", "Error"), ("cause_code", "ETIMEDOUT")):
            with self.subTest(key=key, value=value):
                trace, calls = observer_fixture("after_fetch")
                next(row for row in trace if row["event"] == "socket_error")[key] = value
                with self.assertRaisesRegex(ValueError, "not the pinned informational disposal"):
                    self.audit(trace, calls)

    def test_visible_error_end_and_close_each_have_one_occurrence(self):
        for event in ("socket_error", "socket_end", "socket_close"):
            with self.subTest(event=event):
                trace, calls = observer_fixture("after_fetch")
                if event == "socket_end":
                    row = {"schema": 1, "phase": "metadata", "event": event, "connection_id": "42:connection:1"}
                    trace.insert(-2, row)
                else:
                    row = next(item for item in trace if item["event"] == event)
                trace.insert(trace.index(row) + 1, deepcopy(row))
                number_observer(trace, calls)
                with self.assertRaisesRegex(ValueError, "repeated socket lifecycle event"):
                    self.audit(trace, calls)

    def test_close_error_flag_requires_the_exact_visible_info(self):
        for schedule, flag in (("after_fetch", False), ("after_fetch", "UNKNOWN"), ("clean_closed", True)):
            with self.subTest(schedule=schedule, flag=flag):
                trace, calls = observer_fixture(schedule)
                next(row for row in trace if row["event"] == "socket_close")["had_error"] = flag
                with self.assertRaisesRegex(ValueError, "error flag lacks its exact informational observation"):
                    self.audit(trace, calls)

    def test_no_connection_event_can_follow_close(self):
        for event in ("socket_error", "socket_end"):
            with self.subTest(event=event):
                trace, calls = observer_fixture("after_fetch")
                if event == "socket_error":
                    row = next(item for item in trace if item["event"] == event)
                    trace.remove(row)
                else:
                    row = {"schema": 1, "phase": "metadata", "event": event, "connection_id": "42:connection:1"}
                trace.insert(-1, row)
                number_observer(trace, calls)
                with self.assertRaisesRegex(ValueError, "socket event after close"):
                    self.audit(trace, calls)

    def test_info_does_not_replace_full_fetch_or_its_original_ledger(self):
        trace, calls = observer_fixture("after_fetch")
        trace.remove(next(row for row in trace if row["event"] == "fetch_body_complete"))
        number_observer(trace, calls)
        with self.assertRaisesRegex(ValueError, "original event count: fetch_body_complete"):
            self.audit(trace, calls)
        trace, calls = observer_fixture("after_fetch")
        next(row for row in trace if row["event"] == "call_observation_finished")["outcome"] = "failed"
        with self.assertRaisesRegex(ValueError, "terminal lost original identities/completeness"):
            self.audit(trace, calls)
        trace, calls = observer_fixture("after_fetch")
        calls["1"]["response"]["monotonic_ns"] = "1"
        with self.assertRaisesRegex(ValueError, "differs from complete original Fetch ledger"):
            self.audit(trace, calls)

    def test_request_error_failure_and_incomplete_markers_are_still_forbidden(self):
        for event in ("request_error", "fetch_failure", "observation_incomplete"):
            with self.subTest(event=event):
                trace, calls = observer_fixture("after_fetch")
                trace.insert(-1, {"schema": 1, "phase": "metadata", "event": event, "call_id": "metadata:42:1", "error_code": "UND_ERR_INFO"})
                number_observer(trace, calls)
                with self.assertRaisesRegex(ValueError, "sidecar incomplete/failed/unplanned"):
                    self.audit(trace, calls)
        trace, calls = observer_fixture("info_open")
        trace[-1]["observation_status"] = "INCOMPLETE"
        with self.assertRaisesRegex(ValueError, "final completeness missing"):
            self.audit(trace, calls)

    def test_remaining_connections_equals_the_visible_unclosed_identities(self):
        for schedule, remaining in (("after_fetch", 1), ("info_open", 0), ("clean_open", 0)):
            with self.subTest(schedule=schedule):
                trace, calls = observer_fixture(schedule)
                trace[-1]["remaining_connections"] = remaining
                with self.assertRaisesRegex(ValueError, "remaining connection inventory differs"):
                    self.audit(trace, calls)

    def test_socket_error_must_own_its_identity_without_hidden_request_aliases(self):
        trace, calls = observer_fixture("after_fetch")
        del next(row for row in trace if row["event"] == "socket_error")["connection_id"]
        with self.assertRaisesRegex(ValueError, "lacks its own connection identity"):
            self.audit(trace, calls)
        trace, calls = observer_fixture("after_fetch")
        next(row for row in trace if row["event"] == "socket_error")["request_id"] = "metadata:42:9:request:1"
        with self.assertRaisesRegex(ValueError, "socket observation fields changed"):
            self.audit(trace, calls)


class RawTests(unittest.TestCase):
    def test_complete_raw_roundtrip(self):
        original = b"\0\xff{}\n"
        self.assertEqual(oracle.raw_bytes(oracle.pack(original)), original)

    def test_raw_length_bool_is_not_a_count(self):
        value = oracle.pack(b"x")
        value["body_bytes"] = True
        with self.assertRaisesRegex(ValueError, "bytes/length/SHA"):
            oracle.raw_bytes(value)

    def test_raw_digest_and_extent_are_not_ignored(self):
        for key, value in (("body_sha256", "0" * 64), ("body_bytes", 2)):
            changed = oracle.pack(b"x")
            changed[key] = value
            with self.assertRaises(ValueError):
                oracle.raw_bytes(changed)

    def test_raw_base64_requires_padding_and_exact_bits(self):
        for value in ("eA", "eB==", " eA==", "eA==\n"):
            changed = oracle.pack(b"x")
            changed["body_base64"] = value
            with self.assertRaises(ValueError):
                oracle.raw_bytes(changed)

    def test_duplicate_json_and_nonfinite_are_rejected(self):
        for value in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValueError):
                oracle.parse(value)

    def test_noncanonical_but_valid_object_bytes(self):
        path, raw = object_frame(spacing=True)
        payload, tail = oracle.frame(raw, path)
        self.assertEqual(payload, {"kind": "manifest", "value": {"page_count": 0, "root": None}})
        self.assertEqual(tail, b"")
        self.assertNotEqual(raw, object_frame()[1])

    def test_frame_key_scope_and_extent(self):
        path, raw = object_frame()
        variants = [(path.replace("/storage/1/", "/storage/2/"), raw),
                    (path.replace("/2101/", "/2102/"), raw), (path, raw + b"x"),
                    (path[:-1] + ("0" if path[-1] != "0" else "1"), raw)]
        for key, value in variants:
            with self.subTest(key=key, size=len(value)), self.assertRaises(ValueError):
                oracle.frame(value, key)

    def test_exact_head_scope_and_storage(self):
        head = base_head("success")
        self.assertEqual(oracle.head(encoded(head), "success"), head)
        for change in ({"storage": {"active_generation": 2, "allocated_through": 2}},
                       {"scope": {**head["scope"], "incarnation": 2}}, {"head_serial": 3}):
            with self.assertRaises(ValueError):
                oracle.head(encoded({**head, **change}), "success")

    def test_original_ledger_gap_and_wrong_clock_type(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x.jsonl"
            for sequence, clock in ((2, 1), (1, "1")):
                path.write_text(json.dumps({"schema": 1, "sequence": sequence, "monotonic_ns": clock, "event": "x"}) + "\n")
                with self.assertRaises(ValueError):
                    oracle.rows(directory, path.name)

    def test_exact_lifecycle_requires_each_handler_terminal(self):
        item = exchange(1, "success", "GET", response_raw=encoded(base_head("success")))
        shared = {"schema": 1, "listener_id": "s3-M", "handler_id": "s3-M:1", "worker": "M", "channel": "s3"}
        start = {**shared, "sequence": 1, "monotonic_ns": 1010, "event": "handler_started"}
        end = {**shared, "sequence": 6, "monotonic_ns": 1030, "event": "handler_finished", "failed": False}
        trace = [start, *[item[key] for key in ("request", "forwarded", "response", "terminal")], end]
        for number, row in enumerate(trace, 1):
            row["sequence"] = number
        exchanges, handlers = oracle.exchange_rows(trace, "s3")
        self.assertEqual((len(exchanges), len(handlers)), (1, 1))
        with self.assertRaisesRegex(ValueError, "handler end"):
            oracle.exchange_rows(trace[:-1], "s3")

    def test_handler_cannot_hide_an_empty_extra_connection(self):
        common = {"schema": 1, "listener_id": "s3-M", "handler_id": "s3-M:1", "worker": "M", "channel": "s3"}
        trace = [{**common, "sequence": 1, "monotonic_ns": 1, "event": "handler_started"},
                 {**common, "sequence": 2, "monotonic_ns": 2, "event": "handler_finished", "failed": False}]
        with self.assertRaisesRegex(ValueError, "handler hidden"):
            oracle.exchange_rows(trace, "s3")

    def test_two_requests_cannot_share_one_handler_and_hide_an_empty_failed_handler(self):
        trace = []
        for serial in (1, 2):
            item = exchange(serial, "success", "GET", response_raw=encoded(base_head("success")))
            common = {"schema": 1, "listener_id": "s3-M", "handler_id": "s3-M:" + str(serial),
                      "worker": "M", "channel": "s3"}
            trace.append({**common, "monotonic_ns": 990 + 20 * serial, "event": "handler_started"})
            trace.extend(item[key] for key in ("request", "forwarded", "response", "terminal"))
            trace.append({**common, "monotonic_ns": 1010 + 20 * serial, "event": "handler_finished", "failed": False})
        trace.sort(key=lambda row: row["monotonic_ns"])
        for number, row in enumerate(trace, 1):
            row["sequence"] = number
        exchanges, handlers = oracle.exchange_rows(trace, "s3")
        self.assertEqual((len(exchanges), len(handlers)), (2, 2))

        changed = deepcopy(trace)
        for row in changed:
            if row.get("request_serial") == 2:
                row["handler_id"] = "s3-M:1"
            if row["event"] == "handler_finished":
                if row["handler_id"] == "s3-M:1":
                    row["monotonic_ns"] = 1060
                else:
                    row["failed"] = True
        changed.sort(key=lambda row: row["monotonic_ns"])
        for number, row in enumerate(changed, 1):
            row["sequence"] = number
        self.assertEqual(sum(row["event"] == "object_request" for row in changed), 2)
        self.assertEqual(sum(row["event"] == "handler_started" for row in changed), 2)
        with self.assertRaisesRegex(ValueError, "handler hidden or reused"):
            oracle.exchange_rows(changed, "s3")

    def test_delivery_cannot_change_original_response_bytes(self):
        item = exchange(1, "success", "GET", response_raw=encoded(base_head("success")))
        item["terminal"].update(oracle.pack(b"{}", "response_body"))
        with self.assertRaisesRegex(ValueError, "delivery differs"):
            oracle.exchange_rows([item[key] for key in ("request", "forwarded", "response", "terminal")], "s3")

    def test_backend_unknown_is_not_missing_record(self):
        item = exchange(1, "success", "GET", response_raw=encoded(base_head("success")))
        with self.assertRaisesRegex(ValueError, "original exchange"):
            oracle.exchange_rows([item[key] for key in ("request", "forwarded", "terminal")], "s3")


class ContractTests(unittest.TestCase):
    def test_independent_finite_denominators(self):
        self.assertEqual(len(oracle.COMMANDS), 41)
        self.assertEqual(sum(row["worker"] == "M" for row in oracle.COMMANDS), 13)
        self.assertEqual(sum(row["operation"] == "execute" for row in oracle.COMMANDS), 6)
        self.assertEqual(oracle.COMMANDS[-4:][0]["id"], "m_quarantine_bad_status")
        self.assertEqual([row["scope"] for row in oracle.COMMANDS[-4:]], ["known_quarantine"] * 4)

    def test_original_actions_bind_revision_guard_and_nonce(self):
        self.assertEqual(oracle.action("m_stale_takeover"), {"version": 1, "scope": oracle.SCOPES["stale_412"], "operation": "takeover",
                         "expected_revision": "4", "nonce": "23001", "expected_worker_instance": "8202"})
        self.assertEqual(oracle.action("m_permission_policy")["permissions"], oracle.NEXT_POLICY)

    def test_projection_positive_is_semantic_only(self):
        value = oracle.metadata_semantics(projection_fixture())
        self.assertEqual(value["head_gets"], 13)
        self.assertEqual(value["head_put_attempts"], 4)
        self.assertEqual(value["immutable_io"], 0)

    def test_all_nine_precise_negative_rules(self):
        original = projection_fixture()
        before = oracle.canonical(original)
        for name, rule in controls.CASES:
            with self.subTest(name=name):
                changed, references = controls.mutated(original, name)
                self.assertTrue(references)
                self.assertNotEqual(changed, original)
                with self.assertRaises(oracle.SemanticFailure) as caught:
                    oracle.metadata_semantics(changed)
                self.assertEqual(caught.exception.rule, rule)
        self.assertEqual(oracle.canonical(original), before)

    def test_immutable_negative_has_coherent_original_frame_bytes(self):
        for name in ("immutable_get", "immutable_put", "late_immutable_get"):
            changed, _ = controls.mutated(projection_fixture(), name)
            item = changed["stream"][-1]
            raw = oracle.raw_bytes(item["request"], "request_body") if name == "immutable_put" else oracle.raw_bytes(item["response"], "response_body")
            payload, tail = oracle.frame(raw, item["request"]["path"])
            self.assertEqual((payload["kind"], tail), ("manifest", b""))
            if name == "immutable_put":
                old = projection_fixture()["immutable_samples"][1]
                self.assertNotEqual(item["request"]["path"], old["request"]["path"])
            if name == "late_immutable_get":
                self.assertGreater(oracle.stamp(item["request"]), changed["last_http_response_ns"])
                self.assertLess(oracle.stamp(item["terminal"]), changed["lifetime"]["service_wait4_ns"])

    def test_unknown_not_applied_is_also_rejected(self):
        changed = projection_fixture()
        target = controls.call(changed, "m_put_unknown_policy")
        target["outcome"] = {"ok": False, "error": {"name": "RemoteError", "code": "CONFLICT"}}
        with self.assertRaises(oracle.SemanticFailure) as caught:
            oracle.metadata_semantics(changed)
        self.assertEqual(caught.exception.rule, "M_UNKNOWN_OUTCOME")

    def test_permission_put_rejected_before_denominator(self):
        changed = projection_fixture()
        candidate = oracle.advance(base_head("permission"), 24001, owner_epoch=2, owner_instance=8202, active=False)
        changed["stream"].append(exchange(50, "permission", "PUT", encoded(candidate), if_match=changed["bases"]["permission"]["etag"]))
        with self.assertRaises(oracle.SemanticFailure) as caught:
            oracle.metadata_semantics(changed)
        self.assertEqual(caught.exception.rule, "M_PERMISSION")

    def test_unknown_retry_keeps_original_candidate_bytes(self):
        original = projection_fixture()
        changed, _ = controls.mutated(original, "unknown_second_head_attempt")
        old = controls.put(original, "put_unknown")
        repeated = changed["stream"][-1]
        self.assertEqual(oracle.raw_bytes(old["request"], "request_body"), oracle.raw_bytes(repeated["request"], "request_body"))
        self.assertEqual(old["request"]["if_match"], repeated["request"]["if_match"])
        self.assertEqual(repeated["response"]["status"], 412)

    def test_rebase_mutation_is_a_valid_fresh_shape(self):
        changed, _ = controls.mutated(projection_fixture(), "conflict_rebound_etag")
        item = controls.put(changed, "stale_412")
        value = oracle.head(oracle.raw_bytes(item["request"], "request_body"), "stale_412")
        self.assertEqual((value["revision"], value["head_serial"], value["transition"]["nonce"]), (6, 6, 23001))
        self.assertEqual(item["request"]["if_match"], changed["competitor"]["response"]["etag"])

    def test_copied_projection_does_not_depend_on_evidence_directory(self):
        first = projection_fixture()
        second = json.loads(oracle.canonical(first))
        self.assertEqual(oracle.metadata_semantics(first), oracle.metadata_semantics(second))

    def test_mutation_constructor_refuses_unknown_control(self):
        with self.assertRaisesRegex(ValueError, "unknown independent"):
            controls.mutated(projection_fixture(), "unplanned")

    def test_pinned_head_fields_cannot_disappear(self):
        value = base_head("success")
        del value["head_serial"]
        with self.assertRaisesRegex(ValueError, "HEAD6"):
            oracle.head(encoded(value), "success")

    def test_owned_wait4_requires_actual_kernel_usage(self):
        value = {"wait_status": 0, "kernel_usage": {"available": True, "source": "kernel_wait4_owned_child", "maxrss_bytes": 1,
                                                    "user_seconds": 0.0, "system_seconds": 0.0}}
        oracle.wait4(value, 0)
        for key, replacement in (("available", False), ("source", "poll"), ("maxrss_bytes", True)):
            changed = deepcopy(value)
            changed["kernel_usage"][key] = replacement
            with self.assertRaises(ValueError):
                oracle.wait4(changed, 0)

    def test_git_tree_binds_mode_and_path(self):
        empty = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        files = [{"path": "a", "mode": "100644", "git_blob": empty}]
        expected_bytes = b"100644 a\0" + bytes.fromhex(empty)
        import hashlib
        expected = hashlib.sha1(b"tree " + str(len(expected_bytes)).encode() + b"\0" + expected_bytes).hexdigest()
        self.assertEqual(oracle.git_tree(files), expected)
        self.assertNotEqual(oracle.git_tree([{**files[0], "mode": "100755"}]), expected)
        self.assertNotEqual(oracle.git_tree([{**files[0], "path": "dir/a"}]), expected)


if __name__ == "__main__":
    unittest.main()
