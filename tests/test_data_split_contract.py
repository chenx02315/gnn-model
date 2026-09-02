from __future__ import print_function
import hashlib
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "contracts", "data_split_v1.json")

class DataSplitContractTest(unittest.TestCase):
    def test_preregistered_contract_is_family_isolated_and_seals_blind_test(self):
        with open(PATH, "r", encoding="utf-8") as stream:
            contract = json.load(stream)
        membership = contract["formal_runtime_membership"]
        canonical = json.dumps(membership, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(contract["formal_runtime_membership_sha256"], hashlib.sha256(canonical).hexdigest())
        self.assertEqual("BLOCKED_RECOVERY_AUDIT", contract["status"])
        self.assertTrue(contract["sealed_blind_test"])
        self.assertEqual({"s9234", "s38584", "wb_dma"}, {entry["circuit"] for entry in membership["BLIND_TEST"]})
        self.assertEqual({"b18", "b20", "b21", "b22"}, {entry["circuit"] for entry in membership["PILOT"]})
        circuits, family_roles = set(), {}
        for role in ("TRAIN", "VALIDATION", "PILOT", "BLIND_TEST"):
            for entry in membership[role]:
                self.assertNotIn(entry["circuit"], circuits)
                self.assertEqual(role, family_roles.get(entry["family"], role))
                circuits.add(entry["circuit"]); family_roles[entry["family"]] = role
        self.assertEqual(15, len(circuits))
        self.assertEqual(12, len(family_roles))
        self.assertEqual(7, contract["evidence"]["observed_candidate_circuit_count"])
        self.assertIn("recovery", " ".join(contract["blocking_evidence"]).lower())

    def test_nonformal_pipeline_split_is_family_isolated_and_not_tunable(self):
        with open(PATH, "r", encoding="utf-8") as stream:
            contract = json.load(stream)
        pipeline = contract["pipeline_split_v0"]
        membership = pipeline["membership"]
        canonical = json.dumps(membership, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(pipeline["canonical_membership_sha256"], hashlib.sha256(canonical).hexdigest())
        self.assertFalse(pipeline["thesis_primary_evidence"])
        self.assertFalse(pipeline["runtime_generalization_claim_allowed"])
        self.assertFalse(pipeline["holdout_smoke_may_tune"])
        self.assertFalse(pipeline["training_or_tuning_allowed"])
        family_roles = {}
        for role, entries in membership.items():
            for entry in entries:
                self.assertEqual(role, family_roles.get(entry["family"], role))
                family_roles[entry["family"]] = role
        self.assertTrue(contract["pre_split_access"]["aggregate_counts_maxima_seen"])
        self.assertFalse(contract["pre_split_access"]["candidate_level_future_blind_mapping_seen"])

if __name__ == "__main__": unittest.main()
