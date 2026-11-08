"""Independent overlapping-operation witnesses, not real S3 acceptance."""
from __future__ import annotations

import copy
import unittest

import catalogue_oracle as oracle
from test_catalogue_oracle import Trace, binding, intent, raw


class CatalogueWireOrderTests(unittest.TestCase):
    @staticmethod
    def response(trace, request):
        return next(row for row in trace.a.history if row["event"] == "object_response"
                    and row["request_serial"] == request["request_serial"])

    @staticmethod
    def interval(trace, call, request, begin, end):
        call["monotonic_ns"] = begin - 1
        times = {"object_request": begin, "object_forwarded": begin + 1,
                 "object_response": end, "object_response_delivered": end + 1}
        for row in trace.a.history:
            if row["request_serial"] == request["request_serial"]:
                row["monotonic_ns"] = times[row["event"]]
        trace.a.ends[call["call_id"]] = {"monotonic_ns": end + 2}
        trace.a.history.sort(key=lambda row: row["monotonic_ns"])

    def name_versions(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c)
        puts = [row for row in trace.a.history if row["event"] == "object_request"
                and row["method"] == "PUT" and row["path"] == oracle.name_path(c)]
        return trace, c, puts[0], puts[1]

    def read_reserved(self, *, stale=False):
        trace, c, reserved, bound = self.name_versions()
        previous, replacement = self.response(trace, reserved), self.response(trace, bound)
        call = trace.begin(c, "store_get", key=oracle.name_path(c).removeprefix("/scap-test/"))
        request = trace.exchange(call, "GET", oracle.name_path(c), returned=raw(binding(c)), etag=previous["etag"])
        start = (replacement if stale else previous)["monotonic_ns"] + 1
        finish = replacement["monotonic_ns"] + 10
        self.interval(trace, call, request, start, finish)
        return trace

    def test_old_get_can_finish_after_overlapping_replacement(self):
        trace = self.read_reserved()
        original = copy.deepcopy(trace.a.history)
        trace.wire()
        # The witness order must never rewrite original response timestamps.
        for before, after in zip(original, trace.a.history):
            self.assertEqual(before, {key: value for key, value in after.items() if key != "position"})

    def test_old_get_invoked_after_replacement_finished_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "original invocation/response intervals"):
            self.read_reserved(stale=True).wire()

    def test_new_version_get_can_finish_before_publication_response(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved")
        put = next(row for row in trace.a.history if row["event"] == "object_request"
                   and row["method"] == "PUT" and row["path"] == oracle.name_path(c))
        call = trace.begin(c, "store_get", key=oracle.name_path(c).removeprefix("/scap-test/"))
        request = trace.get(call, oracle.name_path(c))
        self.interval(trace, call, request, put["monotonic_ns"] + 11, put["monotonic_ns"] + 14)
        self.assertLess(self.response(trace, request)["monotonic_ns"], self.response(trace, put)["monotonic_ns"])
        trace.wire()

    def missing_read(self, *, stale=False):
        trace, c, reserved, _ = self.name_versions()
        published = self.response(trace, reserved)
        call = trace.begin(c, "store_get", key=oracle.name_path(c).removeprefix("/scap-test/"))
        request = trace.exchange(call, "GET", oracle.name_path(c), status=404)
        start = published["monotonic_ns"] + 1 if stale else reserved["monotonic_ns"] - 2
        self.interval(trace, call, request, start, published["monotonic_ns"] + 10)
        return trace

    def test_missing_get_can_overlap_first_conditional_create(self):
        self.missing_read().wire()

    def test_missing_get_started_after_create_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "original invocation/response intervals"):
            self.missing_read(stale=True).wire()

    def test_delayed_delivery_logger_is_not_client_consumption_time(self):
        trace = Trace(); trace.prepare(intent())
        delivery = trace.a.history[-1]
        self.assertEqual(delivery["event"], "object_response_delivered")
        delivery["monotonic_ns"] = trace.a.ends[1]["monotonic_ns"] + 100
        trace.wire()

    def test_delivery_cannot_precede_the_actual_backend_response(self):
        trace = Trace(); trace.prepare(intent())
        trace.a.history[-1]["monotonic_ns"] = trace.a.history[-2]["monotonic_ns"]
        with self.assertRaisesRegex(ValueError, "delivery marker preceded"):
            trace.wire()

    def test_failed_cas_cannot_reject_still_current_original_etag(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c, until="reserved")
        path = oracle.name_path(c)
        call = trace.begin(c, "store_put", key=path.removeprefix("/scap-test/"), etag=trace.stored[path][0])
        trace.get(call, path)
        trace.put(call, path, binding(c, "bound"), status=412)
        trace.end(call)
        with self.assertRaisesRegex(ValueError, "still-current exact ETag"):
            trace.wire()

    def test_failed_saved_etag_cas_must_follow_real_successor(self):
        trace, c, reserved, bound = self.name_versions()
        path = oracle.name_path(c)
        old = self.response(trace, reserved)
        winner = self.response(trace, bound)
        call = trace.begin(c, "store_put", key=path.removeprefix("/scap-test/"), etag=old["etag"])
        observed = trace.exchange(call, "GET", path, returned=raw(binding(c)), etag=old["etag"])
        self.interval(trace, call, observed, old["monotonic_ns"] + 1, old["monotonic_ns"] + 4)
        trace.exchange(call, "PUT", path, body=raw(binding(c, "bound")), status=412, condition=old["etag"])
        trace.end(call)
        trace.a.history.sort(key=lambda row: row["monotonic_ns"])
        self.assertLess(old["monotonic_ns"], winner["monotonic_ns"])
        trace.wire()

    def test_accepted_cas_chain_cannot_fork(self):
        trace, c, reserved, _ = self.name_versions()
        path = oracle.name_path(c)
        call = trace.begin(c, "store_put", key=path.removeprefix("/scap-test/"))
        trace.put(call, path, binding(c, "bound"), condition=self.response(trace, reserved)["etag"])
        trace.end(call)
        with self.assertRaisesRegex(ValueError, "same original ETag"):
            trace.wire()

    def damaged(self):
        trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c)
        path = oracle.head_path(c["scope"])
        before = trace.time + 10
        trace.a.facts.extend([
            {"event": "damage_invoked", "case": "unit", "kind": "delete", "key": path.removeprefix("/scap-test/"), "monotonic_ns": before},
            {"event": "damage_observed", "case": "unit", "kind": "delete", "key": path.removeprefix("/scap-test/"), "monotonic_ns": before + 10},
        ])
        trace.time = before + 20
        trace.stored.pop(path)
        call = trace.begin(c, "store_get", key=path.removeprefix("/scap-test/"))
        request = trace.get(call, path); trace.end(call)
        return trace, call, request, before

    def test_explicit_idle_fixture_deletion_allows_later_missing_probe(self):
        trace, _, _, _ = self.damaged()
        wire = trace.wire()
        self.assertTrue(wire.current[oracle.head_path(intent()["scope"])]["missing"])

    def test_fixture_deletion_cannot_explain_unlogged_key_loss(self):
        trace, _, _, _ = self.damaged()
        trace.a.facts = []
        with self.assertRaisesRegex(ValueError, "original invocation/response intervals"):
            trace.wire()

    def test_damage_fixture_must_prove_it_ran_while_key_was_idle(self):
        trace, call, request, before = self.damaged()
        self.interval(trace, call, request, before - 2, before + 20)
        with self.assertRaisesRegex(ValueError, "deletion overlapped"):
            trace.wire()


if __name__ == "__main__":
    unittest.main()
