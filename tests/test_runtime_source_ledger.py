from __future__ import print_function

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "data"))
import build_runtime_source_ledger as ledger_builder


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "src", "data", "build_runtime_source_ledger.py")
LEDGER = os.path.join(ROOT, "data", "manifests", "runtime_source_ledger_v1.json")


class RuntimeSourceLedgerTest(unittest.TestCase):
    def run_ledger(self, output):
        return subprocess.call([sys.executable, SCRIPT, "--repo-root", ROOT, "--output", output])

    def test_checked_in_ledger_rebuilds_byte_identically(self):
        handle, temporary = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        try:
            self.assertEqual(0, self.run_ledger(temporary))
            with open(temporary, "rb") as actual, open(LEDGER, "rb") as expected:
                self.assertEqual(expected.read(), actual.read())
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def test_authority_and_blind_boundaries_are_explicit(self):
        with open(LEDGER, "r") as handle:
            ledger = json.load(handle)
        policy = ledger["phase4_version_policy"]
        self.assertEqual("r6", policy["authoritative"]["version"])
        self.assertEqual("AUTHORITATIVE_NONBLIND", policy["authoritative"]["status"])
        self.assertEqual(["r2", "r3"], [item["version"] for item in policy["historical_only"]])
        self.assertFalse(ledger["validation"]["external_artifacts_reread_locally"])
        self.assertIn("No BLIND candidate", ledger["blind_policy"])
        self.assertNotIn("P0 unblocked", json.dumps(ledger, sort_keys=True))

    def test_phase2_audit_and_sha_validation_are_recorded(self):
        with open(LEDGER, "r") as handle:
            ledger = json.load(handle)
        self.assertEqual("PASS", ledger["phase2_wall_time_semantics"]["validation_status"])
        self.assertEqual(4609, ledger["phase2_wall_time_semantics"]["row_count"])
        self.assertTrue(ledger["validation"]["all_nested_referenced_sha256_lowercase_hex"])
        self.assertGreater(ledger["validation"]["nested_referenced_sha256_field_count"], 10)
        self.assertTrue(ledger["validation"]["all_local_cross_references_match"])
        self.assertEqual(20, ledger["validation"]["local_cross_reference_binding_count"])

    def test_tampered_r6_nested_hash_is_rejected(self):
        summary_path = os.path.join(ROOT, "data", "manifests", "phase4_runtime_nonblind_v2_r6", "summary_r6.json")
        with open(summary_path, "r") as handle:
            summary = json.load(handle)
        summary["circuits"]["b20"]["file_sha256"]["inventory_json"] = "0" * 64
        inputs = ledger_builder.artifact_inputs(ROOT)
        hashes = ledger_builder.checked_in_hashes(ROOT, inputs)
        with self.assertRaises(ValueError):
            ledger_builder.validate_r6_local_bindings(ROOT, summary, hashes)

    def test_tampered_tool_receipt_entry_is_rejected(self):
        original = ledger_builder.parse_sha_file
        try:
            ledger_builder.parse_sha_file = lambda path: dict(
                (name, "0" * 64) for name in ledger_builder.R6_TOOL_TARGETS)
            with open(os.path.join(ROOT, "data", "manifests", "phase4_runtime_nonblind_v2_r6", "summary_r6.json"), "r") as handle:
                summary = json.load(handle)
            inputs = ledger_builder.artifact_inputs(ROOT)
            hashes = ledger_builder.checked_in_hashes(ROOT, inputs)
            with self.assertRaises(ValueError):
                ledger_builder.validate_r6_local_bindings(ROOT, summary, hashes)
        finally:
            ledger_builder.parse_sha_file = original


if __name__ == "__main__":
    unittest.main()
