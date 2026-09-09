from __future__ import print_function
import hashlib
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "contracts", "recommendation_method_registry_v1.json")
PILOT = os.path.join(ROOT, "contracts", "p6_pilot_matrix_v1.json")


class RecommendationMethodRegistryTest(unittest.TestCase):
    def test_method_set_matches_frozen_pilot_contract(self):
        with open(REGISTRY, "r", encoding="utf-8") as stream:
            registry = json.load(stream)
        with open(PILOT, "rb") as stream:
            payload = stream.read()
        pilot = json.loads(payload.decode("utf-8"))
        self.assertEqual(hashlib.sha256(payload).hexdigest(),
                         registry["source_contract_sha256"])
        self.assertEqual(pilot["methods"], registry["methods"])
        self.assertEqual(len(registry["methods"]), registry["method_count"])
        self.assertEqual(len(registry["methods"]), len(set(registry["methods"])))

    def test_binding_is_common_and_deferred_until_after_reseal(self):
        with open(REGISTRY, "r", encoding="utf-8") as stream:
            registry = json.load(stream)
        policy = registry["binding_policy"]
        self.assertTrue(policy["all_methods_must_use_identical_hash"])
        self.assertFalse(policy["method_specific_exclusion_allowed"])
        self.assertIn("after reseal", policy["binding_time"])
        self.assertFalse(registry["training_allowed"])


if __name__ == "__main__":
    unittest.main()
