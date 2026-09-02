from __future__ import print_function
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "contracts", "runtime_policy_v1.json")


class RuntimePolicyContractTest(unittest.TestCase):
    def test_cost_accounting_and_fair_cache_policy_are_frozen(self):
        with open(PATH, "r", encoding="utf-8") as stream:
            policy = json.load(stream)
        self.assertEqual("FROZEN_FOR_PILOT", policy["status"])
        self.assertEqual((60, 30, 30), tuple(policy["timeouts"][key] for key in ("H_s", "M_s", "F_s")))
        self.assertFalse(policy["timeouts"]["timeout_retry_allowed"])
        self.assertTrue(policy["retry"]["charge_all_attempts"])
        self.assertFalse(policy["retry"]["select_fastest_success"])
        self.assertFalse(policy["cache"]["cross_method_artifact_reuse"])
        self.assertFalse(policy["cache"]["cross_session_artifact_reuse"])
        self.assertEqual("within_same_search_session_only", policy["prefix_reuse"]["scope"])
        self.assertEqual("disable_for_all_methods", policy["prefix_reuse"]["fallback_if_audit_unavailable"])
        self.assertFalse(policy["fallback"]["cost_in_primary_endpoint"])
        self.assertTrue(policy["fallback"]["cost_in_online_end_to_end"])
        self.assertEqual("missing_label_no_imputation", policy["missing_historical_timing"]["policy"])
        self.assertFalse(policy["missing_historical_timing"]["runtime_head_eligible"])


if __name__ == "__main__":
    unittest.main()
