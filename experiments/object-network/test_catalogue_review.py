"""Independent interval and saved-candidate counterexamples; no S3 acceptance."""
from __future__ import annotations

import copy
import unittest

import catalogue_oracle as oracle
from test_catalogue_oracle import Trace, binding, intent, raw


def response(trace, request):
    return next(row for row in trace.a.history if row["event"] == "object_response"
                and row["request_serial"] == request["request_serial"])


def interval(trace, call, request, begin, end):
    assert begin + 1 < end
    call["monotonic_ns"] = begin - 1
    times = {"object_request": begin, "object_forwarded": begin + 1,
             "object_response": end, "object_response_delivered": end + 1}
    for row in trace.a.history:
        if row["request_serial"] == request["request_serial"]:
            row["monotonic_ns"] = times[row["event"]]
    trace.a.ends[call["call_id"]] = {"monotonic_ns": end + 2}
    trace.a.history.sort(key=lambda row: row["monotonic_ns"])


def name_versions():
    trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c)
    puts = [row for row in trace.a.history if row["event"] == "object_request"
            and row["method"] == "PUT" and row["path"] == oracle.name_path(c)]
    return trace, c, puts[0], puts[1]


def delayed_candidate(*, another_case=False, public_call=False):
    trace, c, reserved, bound = name_versions()
    path = oracle.name_path(c)
    old = response(trace, reserved)
    if public_call:
        call = trace.begin(c, "catalogue_resume", creation=c)
    else:
        call = trace.begin(c, "store_put", key=path.removeprefix("/scap-test/"),
                           etag=old["etag"], bytes=list(raw(binding(c, "bound"))))
    call["worker"] = 50002
    if another_case:
        call["case"] = "another-case"
    request = trace.put(call, path, binding(c, "bound"), status=412, condition=old["etag"])
    trace.end(call)
    return trace, call, request, bound


def deleted_head():
    trace = Trace(); c = intent(); trace.prepare(c); trace.resume(c)
    path = oracle.head_path(c["scope"])
    saved = trace.stored[path]
    before = trace.time + 10
    trace.a.facts.extend([
        {"event": "damage_invoked", "case": "unit", "kind": "delete",
         "key": path.removeprefix("/scap-test/"), "monotonic_ns": before},
        {"event": "damage_observed", "case": "unit", "kind": "delete",
         "key": path.removeprefix("/scap-test/"), "monotonic_ns": before + 10},
    ])
    trace.time = before + 20
    trace.stored.pop(path)
    return trace, c, path, saved


class CatalogueIndependentReviewTests(unittest.TestCase):
    def test_new_version_cannot_be_read_before_its_first_publication_is_invoked(self):
        trace, c, reserved, _ = name_versions()
        path = oracle.name_path(c)
        original = response(trace, reserved)
        call = trace.begin(c, "store_get", key=path.removeprefix("/scap-test/"))
        request = trace.exchange(call, "GET", path, etag=original["etag"], returned=raw(binding(c)))
        interval(trace, call, request, reserved["monotonic_ns"] - 20, reserved["monotonic_ns"] - 10)
        with self.assertRaisesRegex(ValueError, "original invocation/response intervals"):
            trace.wire()

    def test_412_cannot_precede_the_actual_successor_invocation(self):
        trace, call, request, bound = delayed_candidate()
        interval(trace, call, request, bound["monotonic_ns"] - 9, bound["monotonic_ns"] - 2)
        with self.assertRaisesRegex(ValueError, "original invocation/response intervals"):
            trace.wire()

    def test_cross_worker_saved_candidate_can_use_its_original_case_observation(self):
        trace, call, _, _ = delayed_candidate()
        self.assertFalse(any(row["event"] == "object_response" and row["method"] == "GET"
                             and row["phase"] == call["phase"] for row in trace.a.history))
        before = copy.deepcopy(trace.a.history)
        trace.wire()
        for original, observed in zip(before, trace.a.history):
            self.assertEqual(original, {key: value for key, value in observed.items() if key != "position"})

    def test_saved_candidate_cannot_borrow_another_cases_etag_observation(self):
        trace, _, _, _ = delayed_candidate(another_case=True)
        with self.assertRaisesRegex(ValueError, "same-call exact GET ETag"):
            trace.wire()

    def test_public_reentry_cannot_use_the_fixture_saved_candidate_exception(self):
        trace, _, _, _ = delayed_candidate(public_call=True)
        with self.assertRaisesRegex(ValueError, "same-call exact GET ETag"):
            trace.wire()

    def test_saved_candidate_input_must_keep_the_original_condition(self):
        trace, call, _, bound = delayed_candidate()
        call["command"]["etag"] = response(trace, bound)["etag"]
        with self.assertRaisesRegex(ValueError, "saved fixture candidate changed ETag"):
            trace.wire()

    def test_existing_version_bytes_cannot_change_under_its_opaque_etag(self):
        trace, c, _, bound = name_versions()
        path = oracle.name_path(c)
        call = trace.begin(c, "store_get", key=path.removeprefix("/scap-test/"))
        trace.exchange(call, "GET", path, etag=response(trace, bound)["etag"], returned=raw(binding(c)))
        trace.end(call)
        with self.assertRaisesRegex(ValueError, "complete original body"):
            trace.wire()

    def test_delete_completion_without_an_invocation_cannot_explain_404(self):
        trace, c, path, _ = deleted_head()
        trace.a.facts = [row for row in trace.a.facts if row["event"] != "damage_invoked"]
        call = trace.begin(c, "store_get", key=path.removeprefix("/scap-test/"))
        trace.get(call, path); trace.end(call)
        with self.assertRaisesRegex(ValueError, "deletion lacks one original invocation"):
            trace.wire()

    def test_completed_idle_deletion_cannot_be_followed_by_an_old_successful_get(self):
        trace, c, path, (etag, body) = deleted_head()
        call = trace.begin(c, "store_get", key=path.removeprefix("/scap-test/"))
        trace.exchange(call, "GET", path, status=200, etag=etag, returned=body)
        trace.end(call)
        with self.assertRaisesRegex(ValueError, "original invocation/response intervals"):
            trace.wire()

    def test_completed_idle_deletion_cannot_hide_a_later_authority_republication(self):
        trace, c, path, (etag, body) = deleted_head()
        call = trace.begin(c, "store_put", key=path.removeprefix("/scap-test/"), etag=etag, bytes=list(body))
        trace.exchange(call, "PUT", path, body=body, condition=etag)
        trace.end(call)
        with self.assertRaisesRegex(ValueError, "silently republished after fixture deletion"):
            trace.wire()

    def test_fixture_deletion_of_one_key_cannot_explain_another_keys_404(self):
        trace, c, _, _ = deleted_head()
        path = oracle.name_path(c)
        call = trace.begin(c, "store_get", key=path.removeprefix("/scap-test/"))
        trace.exchange(call, "GET", path, status=404); trace.end(call)
        with self.assertRaisesRegex(ValueError, "original invocation/response intervals"):
            trace.wire()


if __name__ == "__main__":
    unittest.main()
