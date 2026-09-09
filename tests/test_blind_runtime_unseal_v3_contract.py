from __future__ import print_function
import hashlib
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v3.json")
V2 = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v2.json")
REGISTRY = os.path.join(ROOT, "contracts", "recommendation_method_registry_v1.json")


def load(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


class BlindRuntimeUnsealV3ContractTest(unittest.TestCase):
    def test_prior_contract_and_method_registry_are_pinned(self):
        contract = load(PATH)
        self.assertEqual(digest(V2), contract["supersedes"]["sha256"])
        self.assertEqual(digest(REGISTRY), contract["scope"]["method_registry_sha256"])

    def test_one_shot_decides_r06_r07_but_not_method_fairness(self):
        contract = load(PATH)
        self.assertEqual(["R06", "R07"],
                         contract["preconditions"]["checks_measured_by_one_shot_audit"])
        self.assertEqual("R13", contract["preconditions"]["check_derived_after_reseal"])
        self.assertNotIn("method", contract["allowed_receipt"]["circuit_row_fields"])
        self.assertIn("one row per BLIND circuit",
                      contract["allowed_receipt"]["aggregation"])

    def test_candidate_rows_never_leave_sealed_runner(self):
        contract = load(PATH)
        protocol = contract["one_shot_protocol"]
        self.assertTrue(protocol["in_memory_candidate_rows_only"])
        self.assertFalse(protocol["candidate_level_output_allowed"])
        self.assertFalse(protocol["replay_allowed"])
        self.assertEqual(1, protocol["maximum_unseal_attempts"])
        self.assertIn("candidate_level_records",
                      contract["prohibited"]["release_forms"])
        self.assertTrue(contract["allowed_receipt"]["forbid_outcomes"])
        self.assertFalse(contract["training_allowed"])

    def test_r13_uses_post_reseal_common_binding(self):
        rule = load(PATH)["decision_rules"]["R13"]["pass_when"]
        self.assertIn("After reseal", rule)
        self.assertIn("every method", rule)
        self.assertIn("no method-specific exclusion", rule)


if __name__ == "__main__":
    unittest.main()
