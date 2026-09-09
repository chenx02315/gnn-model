from __future__ import print_function
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "data"))
import validate_blind_unseal_preflight as preflight


class BlindUnsealPreflightTest(unittest.TestCase):
    def test_current_repository_passes_without_blind_access(self):
        result = preflight.validate(ROOT)
        self.assertEqual("PASS", result["status"])
        self.assertEqual(["R06", "R07", "R13"],
                         result["assessment_nonpass_checks"])
        self.assertTrue(all(result["checks"].values()))
        self.assertFalse(result["blind_data_read"])
        self.assertFalse(result["candidate_join_performed"])
        self.assertFalse(result["training_allowed"])


if __name__ == "__main__":
    unittest.main()
