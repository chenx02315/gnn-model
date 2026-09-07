from __future__ import print_function
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v1.json")


class BlindRuntimeUnsealContractTest(unittest.TestCase):
    def load_contract(self):
        with open(PATH, "r", encoding="utf-8") as stream:
            return json.load(stream)

    def test_fixed_blind_scope_and_prerequisite_hash_are_frozen(self):
        contract = self.load_contract()
        self.assertEqual("SEALED_ONE_SHOT_COVERAGE_AUDIT_ONLY", contract["status"])
        self.assertEqual(["s9234", "s38584", "wb_dma"], contract["scope"]["blind_circuits"])
        self.assertEqual(3, contract["scope"]["blind_circuit_count"])
        self.assertEqual("c8f589d67d80470dcf49ffbcab51da763162e9ae82af0308b36d6771cbd97cac",
                         contract["scope"]["formal_runtime_membership_sha256"])
        self.assertTrue(contract["preconditions"]["required_split_sealed"])
        required = contract["preconditions"]["required_check_status"]
        self.assertEqual(
            {"R01", "R02", "R03", "R04", "R05", "R06", "R08", "R09", "R10", "R11", "R12", "R14"},
            set(required),
        )
        self.assertTrue(all(status == "PASS" for status in required.values()))
        self.assertEqual(["R07", "R13"], contract["preconditions"]["only_checks_allowed_to_remain_blocked_before_unseal"])
        self.assertTrue(contract["preconditions"]["p0_remains_blocked"])

    def test_roles_and_one_shot_coverage_only_boundary(self):
        contract = self.load_contract()
        self.assertEqual({"blind_custodian", "independent_auditor", "model_or_tuning_operator"},
                         set(contract["roles"]))
        protocol = contract["one_shot_protocol"]
        self.assertEqual(1, protocol["maximum_unseal_attempts"])
        self.assertFalse(protocol["replay_allowed"])
        self.assertIn("coverage-only", protocol["permitted_operation"])
        self.assertTrue(protocol["receipt_only"])
        self.assertIn("reseal", protocol["failure_action"].lower())

    def test_outcomes_and_training_or_tuning_are_prohibited(self):
        contract = self.load_contract()
        forbidden_fields = set(contract["prohibited"]["outcome_or_runtime_fields"])
        self.assertTrue({"elapsed", "wall_time", "runtime_value", "coverage_outcome", "candidate_rank"}.issubset(forbidden_fields))
        forbidden_uses = set(contract["prohibited"]["model_or_tuning_uses"])
        self.assertTrue({"training", "feature_selection", "model_selection", "hyperparameter_tuning",
                         "threshold_tuning", "candidate_order_tuning", "calibration"}.issubset(forbidden_uses))
        self.assertTrue(contract["allowed_receipt"]["forbid_outcomes"])

    def test_receipt_is_aggregate_and_r07_r13_are_conservative(self):
        contract = self.load_contract()
        receipt = contract["allowed_receipt"]
        self.assertIn("per blind circuit and method only", receipt["aggregation"])
        self.assertIn("coverage_rate", receipt["fields"])
        self.assertIn("sha256", " ".join(receipt["fields"]).lower())
        self.assertIn("candidate_level_records", contract["prohibited"]["release_forms"])
        rules = contract["decision_rules"]
        self.assertIn("coverage_rate == 1.0", rules["R07"]["pass_when"])
        self.assertIn("ambiguous_runtime_join_count == 0", rules["R07"]["pass_when"])
        self.assertIn("R07 passes", rules["R13"]["pass_when"])
        self.assertIn("identical", rules["R13"]["pass_when"])
        self.assertIn("every R01 through R14 as PASS", rules["p0"])


if __name__ == "__main__":
    unittest.main()
