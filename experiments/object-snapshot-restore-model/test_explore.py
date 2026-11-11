from collections import Counter
from pathlib import Path
import tempfile
import unittest

from cases import cases, interleave
from counterexamples import negatives
from explore import FAMILIES, inventory, Output
from oracle import audit


class ExploreTests(unittest.TestCase):
    def test_fixed_inventory_and_no_omitted_family(self):
        positive, negative = cases(), negatives()
        table = inventory(positive, negative)
        self.assertEqual(len(table["positive"]), 804)
        self.assertEqual(len(table["negative"]), 47)
        self.assertEqual(dict(Counter(case.family for case in positive)), FAMILIES)

    def test_every_representative_and_all_boundary_histories(self):
        seen = set()
        for case in cases():
            if case.family not in ("boundary", "refinement") and case.family in seen:
                continue
            seen.add(case.family)
            with self.subTest(name=case.name):
                audit(case.build().trace(case.name))

    def test_all_orderings_preserve_each_chain(self):
        rows = list(interleave(("a", "b", "c", "d"), ("x", "y", "z")))
        self.assertEqual(len(rows), 35)
        self.assertEqual(len(set(rows)), 35)
        for row in rows:
            self.assertEqual([item for item in row if item in "abcd"], list("abcd"))
            self.assertEqual([item for item in row if item in "xyz"], list("xyz"))

    def test_evidence_directory_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attempt"
            output = Output(path)
            row = output.save("prefix.json", {"raw": "preserved"})
            with self.assertRaises(FileExistsError):
                Output(path)
            with self.assertRaises(FileExistsError):
                output.save("prefix.json", {"raw": "replaced"})
            self.assertGreater(row["bytes"], 0)
            self.assertIn("preserved", (path / "prefix.json").read_text())


if __name__ == "__main__":
    unittest.main()
