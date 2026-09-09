from __future__ import print_function
import hashlib
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v2.json")
V1 = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v1.json")


class BlindRuntimeUnsealV2ContractTest(unittest.TestCase):
    def load_contract(self):
        with open(PATH, "r", encoding="utf-8") as stream:
            return json.load(stream)

    def test_v1_is_preserved_and_pinned(self):
        contract = self.load_contract()
        with open(V1, "rb") as stream:
            digest = hashlib.sha256(stream.read()).hexdigest()
        self.assertEqual(digest, contract["supersedes"]["sha256"])
        self.assertIn("circularly", contract["supersedes"]["reason"])

    def test_r06_is_measured_inside_the_same_one_shot_audit(self):
        contract = self.load_contract()
        required = contract["preconditions"]["required_check_status"]
        self.assertNotIn("R06", required)
        self.assertEqual(
            ["R06", "R07", "R13"],
            contract["preconditions"]["checks_measured_jointly_by_one_shot_audit"])
        self.assertEqual(
            ["R06", "R07", "R13"],
            contract["preconditions"]["only_checks_allowed_to_remain_nonpass_before_unseal"])
        self.assertIn("ambiguous_runtime_join_count == 0",
                      contract["decision_rules"]["R06"]["pass_when"])

    def test_receipt_is_atomic_aggregate_only_and_outcome_free(self):
        contract = self.load_contract()
        protocol = contract["one_shot_protocol"]
        self.assertEqual(1, protocol["maximum_unseal_attempts"])
        self.assertFalse(protocol["replay_allowed"])
        self.assertIn("one final aggregate receipt", protocol["atomic_release"])
        self.assertIn("ambiguous_runtime_join_count",
                      contract["allowed_receipt"]["fields"])
        self.assertTrue(contract["allowed_receipt"]["forbid_outcomes"])
        self.assertFalse(contract["training_allowed"])


if __name__ == "__main__":
    unittest.main()
