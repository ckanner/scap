from collections import Counter
import unittest

from explore import interleave, schedules
from oracle import audit


class FiniteProfiles(unittest.TestCase):
    def test_scheduler_exhausts_declared_chain_orders(self):
        for left, right, expected in ((3, 3, 20), (3, 5, 56), (4, 5, 126)):
            a = tuple("a" + str(index) for index in range(left))
            b = tuple("b" + str(index) for index in range(right))
            rows = list(interleave(a, b))
            self.assertEqual(len(rows), expected)
            self.assertEqual(len(set(rows)), expected)
            self.assertTrue(all(tuple(x for x in row if x.startswith("a")) == a and tuple(x for x in row if x.startswith("b")) == b for row in rows))

    def test_each_smoke_parameter_profile_reaches_independent_oracle(self):
        counts = Counter()
        for item in schedules(smoke=True):
            self.assertEqual(audit(item["history"])["events"], len(item["history"]["events"]))
            self.assertTrue(all(item["postconditions"].values()))
            self.assertTrue(item["states"] and item["edges"])
            counts[item["profile"]] += 1
        self.assertEqual(counts, {"terminal-race": 16, "late-put": 4, "late-get": 2,
                                  "late-head": 7, "restart-terminal": 16, "restart-gc": 4,
                                  "foreign-abort": 4})


if __name__ == "__main__":
    unittest.main()
