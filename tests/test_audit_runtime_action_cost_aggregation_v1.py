from __future__ import print_function

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))
import audit_runtime_action_cost_aggregation_v1 as review


class ReviewHelperTests(unittest.TestCase):
    def test_formatted_is_stable(self):
        import decimal
        self.assertEqual("1.234567891", review.formatted(decimal.Decimal("1.2345678914")))

    def test_rejects_existing_output_before_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt=pathlib.Path(directory)/"receipt.json"
            receipt.write_text(json.dumps({}),encoding="utf-8")
            with self.assertRaises(review.ReviewError):
                review.review("missing","missing","missing","missing",str(receipt))


if __name__ == "__main__":
    unittest.main()
