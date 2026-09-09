from __future__ import print_function

import json
import os
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTOCOL_PATH = os.path.join(ROOT, "contracts", "blind_runtime_unseal_protocol_v7.json")


class BlindUnsealProtocolV7Test(unittest.TestCase):
    def setUp(self):
        with open(PROTOCOL_PATH, "r", encoding="utf-8") as stream:
            self.protocol = json.load(stream)

    def test_operational_state_machine_is_complete_and_ordered(self):
        machine = self.protocol["state_machine"]
        self.assertEqual("FROZEN", self.protocol["status"])
        self.assertEqual(
            ["FROZEN", "REGISTERED_HELD", "REVIEW_PASS", "RESUMED_ONCE",
             "CONSUMED", "RELEASED_VERIFIED"],
            machine["ordered_states"])
        self.assertEqual("RELEASED_VERIFIED", machine["terminal_state"])
        self.assertIn("CONSUMED_to_RESUMED_ONCE", machine["forbidden_transitions"])

    def test_held_lsf_registration_is_precise_and_unassigned(self):
        registration = self.protocol["registration"]
        self.assertEqual("two_phase_held_lsf_job", registration["registration_mode"])
        self.assertIsNone(registration["job_id"])
        self.assertEqual("PSUSP", registration["held_job_requirements"]["initial_scheduler_state"])
        self.assertFalse(registration["held_job_requirements"]["array_allowed"])
        self.assertFalse(registration["held_job_requirements"]["rerun_allowed"])
        self.assertFalse(registration["held_job_requirements"]["requeue_allowed"])
        self.assertFalse(registration["held_job_requirements"]["retry_allowed"])
        self.assertEqual("bresume <registered_job_id>",
                         registration["held_job_requirements"]["only_resume_command"])
        required = set(registration["required_immutable_fields"])
        self.assertTrue({"job_id", "git_commit", "protocol_sha256", "gate_snapshot_sha256",
                         "command_argv", "queue", "resource_request", "cwd",
                         "stdout_path", "stderr_path"}.issubset(required))

    def test_pass_receipt_and_release_audit_are_required(self):
        review = self.protocol["review_gate"]
        audit = self.protocol["execution_and_audit"]
        self.assertEqual("PASS", review["required_status"])
        self.assertTrue(review["receipt_must_bind_registration_exactly"])
        self.assertEqual({"no_blind_parse": True, "no_blind_output": True},
                         review["required_no_blind_flags"])
        self.assertFalse(review["resume_before_pass_allowed"])
        self.assertEqual(["CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED"],
                         audit["canonical_release_artifacts"])
        self.assertEqual(["bhist", "bacct"], audit["required_scheduler_evidence"])
        self.assertEqual(5, audit["HIST_HOURS"])

    def test_claim_boundary_rejects_same_account_adversarial_irreversibility(self):
        threat_model = self.protocol["threat_model"]
        prohibition = self.protocol["prohibitions"]
        boundary = threat_model["claim_boundary"].lower()
        self.assertIn("operational", boundary)
        self.assertIn("not claim", boundary)
        self.assertIn("same-user", boundary)
        self.assertIn("a same-account adversary who can delete or recreate state",
                      threat_model["not_protected_against"])
        self.assertFalse(prohibition["same_account_adversarial_irreversibility_claim_allowed"])
        self.assertFalse(prohibition["training_before_released_verified_allowed"])


if __name__ == "__main__":
    unittest.main()
