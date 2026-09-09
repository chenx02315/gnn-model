from __future__ import print_function

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "data"))
import audit_blind_attempt_preconditions as blind_audit


class BlindAttemptPreconditionAuditTest(unittest.TestCase):
    def test_checked_in_aggregate_receipts_match_contract_and_repeat_hashes(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        receipt_dir = os.path.join(repo, "data", "manifests",
                                   "blind_attempt_preconditions_v1")
        with open(os.path.join(repo, "contracts",
                               "blind_attempt_preconditions_v1.json"), "r") as handle:
            contract = json.load(handle)
        with open(os.path.join(receipt_dir, "assessment.json"), "r") as handle:
            assessment = json.load(handle)

        first = {}
        repeat = {}
        for filename, target in (("aggregate_outputs.sha256", first),
                                 ("repeat_outputs.sha256", repeat)):
            with open(os.path.join(receipt_dir, filename), "r") as handle:
                for line in handle:
                    digest, remote_path = line.strip().split(None, 1)
                    circuit = os.path.basename(remote_path).split(".")[0]
                    target[circuit] = digest
        self.assertEqual(first, repeat)

        total = 0
        for circuit, expected_count in contract["required_counts"].items():
            path = os.path.join(receipt_dir, circuit + ".json")
            with open(path, "rb") as handle:
                payload = handle.read()
            receipt = json.loads(payload.decode("utf-8"))
            self.assertEqual(first[circuit], hashlib.sha256(payload).hexdigest())
            self.assertEqual(expected_count,
                             receipt["counts"]["recovered_attempt_count"])
            for key in contract["required_true_validations"]:
                self.assertTrue(receipt["validation"][key], key)
            for key in contract["required_false_validations"]:
                self.assertFalse(receipt["validation"][key], key)
            self.assertEqual(first[circuit],
                             assessment["circuits"][circuit]["receipt_sha256"])
            total += expected_count
        self.assertEqual(total, assessment["total_attempt_count"])

    def test_aggregate_gate_retains_rows_and_hides_row_level_values(self):
        original = blind_audit.gnu_rows
        try:
            blind_audit.gnu_rows = lambda _path, _root, meta, _extra: [
                {
                    "attempt_id": "a1", "parse_status": "PASS",
                    "retry_order_status": "UNKNOWN_ORDER", "phase": meta["phase"],
                    "cohort": meta["cohort"],
                    "environment_cohort": meta["environment_cohort"],
                    "source_artifact_sha256": "a" * 64,
                    "inventory_manifest_sha256": meta["inventory_manifest_sha256"],
                    "run_id": "must-not-leak", "wall_s": "12.3",
                },
                {
                    "attempt_id": "a2", "parse_status": "MISSING_EXIT",
                    "retry_order_status": "UNKNOWN_ORDER", "phase": meta["phase"],
                    "cohort": meta["cohort"],
                    "environment_cohort": meta["environment_cohort"],
                    "source_artifact_sha256": "b" * 64,
                    "inventory_manifest_sha256": meta["inventory_manifest_sha256"],
                    "source_log_path": "must-not-leak",
                },
            ]
            meta = {
                "circuit": "sealed", "family": "blind", "role": "BLIND_TEST",
                "phase": "phase4", "cohort": "cohort",
                "environment_cohort": "environment_unverified",
                "inventory_manifest_sha256": "c" * 64,
            }
            result = blind_audit.audit("input", "root", meta, "c" * 64)
            self.assertEqual(2, result["counts"]["recovered_attempt_count"])
            for key in (
                    "all_discovered_logs_retained",
                    "all_attempt_ids_unique",
                    "all_attempts_have_parse_status",
                    "all_attempts_have_source_digest",
                    "all_attempts_bind_inventory",
                    "all_attempts_record_phase",
                    "all_attempts_record_cohort",
                    "all_attempts_record_environment_cohort",
                    "retry_order_not_imputed"):
                self.assertTrue(result["validation"][key], key)
            self.assertFalse(result["validation"]["fastest_success_selection_performed"])
            self.assertFalse(result["validation"]["candidate_join_performed"])
            self.assertFalse(result["validation"]["blind_row_level_data_released"])
            payload = str(result)
            self.assertNotIn("must-not-leak", payload)
            self.assertNotIn("run_id", payload)
            self.assertNotIn("wall_s", payload)
            self.assertNotIn("source_log_path", payload)
        finally:
            blind_audit.gnu_rows = original

    def test_duplicate_attempt_id_fails_uniqueness_boolean(self):
        original = blind_audit.gnu_rows
        try:
            row = {
                "attempt_id": "same", "parse_status": "PASS",
                "retry_order_status": "UNKNOWN_ORDER", "phase": "p",
                "cohort": "c", "environment_cohort": "e",
                "source_artifact_sha256": "a" * 64,
                "inventory_manifest_sha256": "b" * 64,
            }
            blind_audit.gnu_rows = lambda *_args: [dict(row), dict(row)]
            meta = {"circuit": "x", "family": "f", "role": "BLIND_TEST",
                    "phase": "p", "cohort": "c", "environment_cohort": "e",
                    "inventory_manifest_sha256": "b" * 64}
            result = blind_audit.audit("i", "r", meta, "b" * 64)
            self.assertFalse(result["validation"]["all_attempt_ids_unique"])
        finally:
            blind_audit.gnu_rows = original


if __name__ == "__main__":
    unittest.main()
