"""Directed model counterexamples are separate from actual database evidence."""
import copy
import unittest

import model


class GroupModelTests(unittest.TestCase):
    def test_exhaustive_small_schedules(self):
        report = model.explore()
        self.assertEqual(report["schedules"], 2940)
        self.assertGreater(report["accepted"], 0)
        self.assertGreater(report["conflicted"], 0)
        self.assertGreater(report["declined_before_sql"], 0)

    def test_first_middle_last_failure_excludes_unstarted_suffix(self):
        for failed in (1, 2, 3, 4):
            trace = model.run(4, failed=failed)
            self.assertEqual([row["id"] for row in trace if row["event"] == "execute"], list(range(1, failed + 1)))
            self.assertEqual([row["id"] for row in trace if row["event"] == "staged"], list(range(1, failed)))

    def test_lost_response_retains_each_original_result_without_ack(self):
        trace = model.run(4, fault="lost_cas_response")
        self.assertEqual(len(trace[-1]["results"]), 4)
        self.assertTrue(all(row["outcome"] == "unknown" for row in trace if row["event"] == "reply"))

    def test_refreshing_etag_cannot_rescue_old_group(self):
        trace = model.run(4, control="cancel", control_at=6)
        candidate = next(row for row in trace if row["event"] == "cas")
        candidate["if_match"] += 1
        with self.assertRaisesRegex(AssertionError, "fresh ETag"):
            model.audit(trace)

    def test_all_dependencies_must_be_verified_before_head(self):
        trace = model.run(3)
        trace.remove(next(row for row in trace if row["event"] == "verify"))
        with self.assertRaisesRegex(AssertionError, "unverified"):
            model.audit(trace)

    def test_one_group_revision_cannot_replace_independent_member_revisions(self):
        trace = model.run(3)
        next(row for row in trace if row["event"] == "cas")["head"].revision -= 2
        with self.assertRaisesRegex(AssertionError, "share"):
            model.audit(trace)

    def test_ack_cannot_precede_native_adoption(self):
        trace = model.run(2)
        trace.remove(next(row for row in trace if row["event"] == "adopt"))
        with self.assertRaisesRegex(AssertionError, "ACK preceded"):
            model.audit(trace)

    def test_suffix_sql_cannot_run_after_member_failure(self):
        trace = model.run(4, failed=2)
        index = next(index for index, row in enumerate(trace) if row["event"] == "member_failed")
        trace.insert(index + 1, {"event": "execute", "id": 3})
        with self.assertRaisesRegex(AssertionError, "failed member"):
            model.audit(trace)

    def test_failed_cas_does_not_authorize_replay(self):
        trace = model.run(3, control="owner", control_at=5)
        index = next(index for index, row in enumerate(trace) if row["event"] == "cas")
        trace.insert(index + 1, {"event": "execute", "id": 1})
        with self.assertRaisesRegex(AssertionError, "conflict"):
            model.audit(trace)

    def test_failed_cas_cannot_repeat_the_same_candidate_and_etag(self):
        trace = model.run(3, control="owner", control_at=5)
        index = next(index for index, row in enumerate(trace) if row["event"] == "cas")
        trace.insert(index + 1, copy.deepcopy(trace[index]))
        with self.assertRaisesRegex(AssertionError, "retried its original CAS"):
            model.audit(trace)

    def test_cold_lookup_cannot_synthesize_new_random_results(self):
        trace = model.run(3)
        trace[-1]["results"][2] = (5, 7, 999)
        with self.assertRaisesRegex(AssertionError, "regenerated"):
            model.audit(trace)


if __name__ == "__main__":
    unittest.main()
