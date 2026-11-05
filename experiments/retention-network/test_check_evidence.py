"""Focused regressions for the deployment evidence checkers, without daemons."""

from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
RETENTION = load("retention_evidence", HERE / "check_evidence.py")
HISTORY = load("history_evidence", HERE.parent / "history-network" / "check_evidence.py")
REQUEST_ID = "0" * 31 + "1"


def logical(kind="write", epoch="2", outcome="success", **changes):
    return {"ordinal": 0, "database": "alpha", "kind": kind, "request_id": REQUEST_ID,
            "request_epoch": epoch, "outcome": outcome, "invoked_ms": 0, "result_ms": 100, **changes}


def attempt(record, ordinal, probe=False, **changes):
    kind = record["kind"]
    route = ("v2/pipeline" if kind in {"write", "read"} else
             "v1/status" if kind == "status" else
             "v1/request-epoch" if kind == "rotate" else "v1/requests/" + REQUEST_ID)
    return {"ordinal": ordinal, "node_id": 1, "method": "GET" if probe or kind == "status" else "POST",
            "route": "/db/alpha/" + ("v1/status" if probe else route), "request_id": REQUEST_ID,
            "request_epoch": record["request_epoch"], "mode": "read" if kind == "read" else "write",
            "deadline_unix_ms": "1000", "invoked_ms": ordinal * 10 + 1, "result_ms": ordinal * 10 + 2,
            "outcome": "response", "status": 200, "code": None, **changes}


class OperationAttempts(unittest.TestCase):
    def test_successful_capability_get_is_not_a_repeated_write(self):
        record = logical()
        probe, post = attempt(record, 0, True), attempt(record, 1)
        self.assertEqual(RETENTION.operation_http_attempts(record, [probe, post]), [post])

    def test_each_scoped_mutation_requires_its_own_probe(self):
        for kind in ("write", "cancel", "acknowledge", "rotate"):
            with self.subTest(kind=kind):
                record = logical(kind)
                probe, post = attempt(record, 0, True), attempt(record, 1)
                self.assertEqual(RETENTION.operation_http_attempts(record, [probe, post]), [post])
                with self.assertRaisesRegex(AssertionError, "capability probe"):
                    RETENTION.operation_http_attempts(record, [post])

    def test_epoch_one_and_read_operations_do_not_gain_an_extra_probe(self):
        for kind, epoch in (("write", "1"), ("read", "2"), ("lookup", "2"), ("status", "2")):
            with self.subTest(kind=kind):
                record = logical(kind, epoch)
                raw = [attempt(record, 0)]
                self.assertEqual(RETENTION.operation_http_attempts(record, raw), raw)

    def test_not_leader_can_reroute_with_a_new_exact_endpoint_probe(self):
        record = logical()
        raw = [attempt(record, 0, True), attempt(record, 1, code="NOT_LEADER"),
               attempt(record, 2, True, node_id=2), attempt(record, 3, node_id=2)]
        self.assertEqual(RETENTION.operation_http_attempts(record, raw), [raw[1], raw[3]])

    def test_not_leader_on_probe_can_reroute_without_submitting_a_post(self):
        record = logical()
        raw = [attempt(record, 0, True, status=409, code="NOT_LEADER"),
               attempt(record, 1, True, node_id=2), attempt(record, 2, node_id=2)]
        self.assertEqual(RETENTION.operation_http_attempts(record, raw), [raw[2]])

    def test_unknown_transport_loss_late_and_successful_posts_cannot_repeat(self):
        for outcome, code in (("response", "COMMIT_UNKNOWN"), ("transport_error", "TypeError"),
                              ("response_lost", None), ("response", "EXPIRED"),
                              ("response", "REQUEST_RETIRED"), ("response", None)):
            with self.subTest(outcome=outcome, code=code):
                record = logical()
                raw = [attempt(record, 0, True), attempt(record, 1, outcome=outcome, code=code),
                       attempt(record, 2, True, node_id=2), attempt(record, 3, node_id=2)]
                with self.assertRaisesRegex(AssertionError, "repeated after UNKNOWN"):
                    RETENTION.operation_http_attempts(record, raw)

    def test_failed_probe_cannot_be_followed_by_a_mutation_or_another_probe(self):
        for outcome, status, code in (("transport_error", None, "TypeError"),
                                     ("response_lost", 200, None), ("response", 503, "COMMIT_UNKNOWN")):
            for repeat_probe in (False, True):
                with self.subTest(outcome=outcome, repeat_probe=repeat_probe):
                    record = logical(outcome="service_error")
                    raw = [attempt(record, 0, True, outcome=outcome, status=status, code=code),
                           attempt(record, 1, repeat_probe)]
                    with self.assertRaisesRegex(AssertionError, "failed capability probe"):
                        RETENTION.operation_http_attempts(record, raw)

    def test_probe_for_another_node_cannot_authorize_the_post(self):
        record = logical()
        with self.assertRaisesRegex(AssertionError, "another endpoint"):
            RETENTION.operation_http_attempts(record, [attempt(record, 0, True), attempt(record, 1, node_id=2)])

    def test_original_deadline_includes_probe_operation_and_reroute(self):
        record = logical()
        for index in (0, 1, 2, 3):
            with self.subTest(changed_attempt=index):
                raw = [attempt(record, 0, True), attempt(record, 1, code="NOT_LEADER"),
                       attempt(record, 2, True, node_id=2), attempt(record, 3, node_id=2)]
                raw[index]["deadline_unix_ms"] = "1001"
                with self.assertRaisesRegex(AssertionError, "original deadline"):
                    RETENTION.operation_http_attempts(record, raw)

    def test_probes_and_posts_must_be_serial(self):
        record = logical()
        with self.assertRaisesRegex(AssertionError, "overlap"):
            RETENTION.operation_http_attempts(record, [attempt(record, 0, True, result_ms=20), attempt(record, 1)])

    def test_probe_only_is_valid_only_for_an_unsuccessful_call(self):
        for changes in ({}, {"outcome": "transport_error", "status": None, "code": "TypeError"}):
            record = logical(outcome="service_error")
            raw = [attempt(record, 0, True, **changes)]
            self.assertEqual(RETENTION.operation_http_attempts(record, raw), [])
            record["outcome"] = "success"
            with self.assertRaisesRegex(AssertionError, "no real HTTP result"):
                RETENTION.operation_http_attempts(record, raw)

    def test_lost_rotation_response_still_counts_exactly_one_mutation(self):
        record = logical("rotate", "4", "service_error")
        raw = [attempt(record, 0, True), attempt(record, 1, outcome="response_lost")]
        self.assertEqual(RETENTION.operation_http_attempts(record, raw), [raw[1]])

    def test_unknown_route_repeated_probe_or_changed_identity_is_not_ignored(self):
        record = logical()
        valid = [attempt(record, 0, True), attempt(record, 1)]
        mutations = (("method", "GET"), ("route", "/db/alpha/unrelated"),
                     ("request_epoch", "3"), ("request_id", "f" * 32), ("mode", "read"))
        for field, value in mutations:
            with self.subTest(field=field):
                raw = deepcopy(valid)
                raw[1][field] = value
                with self.assertRaises(AssertionError):
                    RETENTION.operation_http_attempts(record, raw)
        with self.assertRaisesRegex(AssertionError, "route or method"):
            RETENTION.operation_http_attempts(record, [attempt(record, 0, True), attempt(record, 1, True)])

    def test_legacy_post_unknown_cannot_repeat_either(self):
        record = logical(epoch="1")
        with self.assertRaisesRegex(AssertionError, "repeated after UNKNOWN"):
            RETENTION.operation_http_attempts(record, [attempt(record, 0, code="COMMIT_UNKNOWN"), attempt(record, 1)])

    def test_explicit_later_call_with_same_identity_has_a_separate_interval(self):
        first = logical("acknowledge", "1", "service_error", result_ms=5)
        second = logical("acknowledge", "1", invoked_ms=10, result_ms=20, ordinal=1)
        rejected = attempt(first, 0, status=409, code="RESOLVE_REJECTED")
        accepted = attempt(second, 1)
        raw = [rejected, accepted]
        self.assertEqual(RETENTION.request_http_attempts(first, raw), [rejected])
        self.assertEqual(RETENTION.request_http_attempts(second, raw), [accepted])
        self.assertEqual(RETENTION.operation_http_attempts(second, [accepted]), [accepted])


class LegacyCancellation(unittest.TestCase):
    def test_old_and_new_sdk_shapes_retain_the_same_legacy_cancellation(self):
        HISTORY.legacy_cancelled({"state": "cancelled"})
        HISTORY.legacy_cancelled({"state": "cancelled", "position": None, "acknowledged": False})

    def test_committed_unknown_and_retired_are_never_relabelled_cancelled(self):
        for state in ("committed", "unknown", "retired"):
            with self.subTest(state=state), self.assertRaisesRegex(AssertionError, "silently treated"):
                HISTORY.legacy_cancelled({"state": state})

    def test_legacy_outcome_cannot_gain_proof_acknowledgement_or_extra_fields(self):
        valid = {"state": "cancelled", "position": None, "acknowledged": False}
        for field, value in (("position", {"term": "1", "index": "2"}), ("acknowledged", True),
                             ("acknowledged", 0), ("results", [])):
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                HISTORY.legacy_cancelled({**valid, field: value})


if __name__ == "__main__":
    unittest.main()
