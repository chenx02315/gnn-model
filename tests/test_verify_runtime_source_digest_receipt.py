from __future__ import print_function

import json
import os
import sys
import tempfile
import unittest
import uuid


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "src", "data")
AUDIT = os.path.join(DATA, "audit_runtime_log_inventory.py")
RECHECK = os.path.join(DATA, "recheck_runtime_source_digests.py")
sys.path.insert(0, DATA)
import recheck_runtime_source_digests as recheck
import verify_runtime_source_digest_receipt as verifier
from tests.test_recheck_runtime_source_digests import frozen_spec


class CanonicalDigestReceiptVerifierTest(unittest.TestCase):
    def write_json(self, path, value):
        with open(path, "w", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")

    def fixture(self, work):
        fixture_root = os.path.join(work, "fixture_" + uuid.uuid4().hex)
        os.mkdir(fixture_root)
        specification = frozen_spec(fixture_root)
        spec_path = os.path.join(fixture_root, "spec.json")
        receipt_path = os.path.join(fixture_root, "receipt.json")
        self.write_json(spec_path, specification)
        receipt = {
            "schema_version": recheck.RECEIPT_SCHEMA,
            "receipt_version": "r03-canonical-18-v2",
            "specification_sha256": recheck.specification_sha256(specification),
            "audit_tool_sha256": recheck.AUDIT_TOOL_SHA256,
            "recheck_tool_sha256": verifier.sha256_file(RECHECK),
            "artifacts": dict((key, recheck.CANONICAL_DIGESTS[key]) for key in
                              sorted(recheck.CANONICAL_VERSIONS["r03-canonical-18-v2"])),
            "counts": {"entry_count": 18, "file_count": 1, "inventory_count": 17},
            "field_policy": "logical IDs, SHA-256 values, and aggregate counts only",
        }
        self.write_json(receipt_path, receipt)
        return spec_path, receipt, receipt_path

    def verify_fixture(self, spec_path, receipt_path, recheck_tool=RECHECK,
                       trusted_recheck_sha256=None, expected_version="r03-canonical-18-v2"):
        return verifier.verify(
            receipt_path, spec_path, verifier.sha256_file(spec_path),
            trusted_recheck_sha256 or verifier.sha256_file(RECHECK),
            expected_version, recheck_tool, AUDIT)

    def test_valid_receipt_is_verified_against_raw_spec_and_actual_tools(self):
        with tempfile.TemporaryDirectory() as work:
            spec_path, _receipt, receipt_path = self.fixture(work)
            result = self.verify_fixture(spec_path, receipt_path)
            self.assertEqual("VERIFIED", result["status"])
            self.assertEqual(18, result["verified_entry_count"])
            self.assertEqual(verifier.sha256_file(spec_path), result["trusted_raw_spec_sha256"])
            self.assertEqual(verifier.sha256_file(RECHECK), result["trusted_recheck_tool_sha256"])
            self.assertEqual(verifier.sha256_file(receipt_path), result["receipt_sha256"])

    def test_tamper_extra_field_wrong_tool_and_wrong_trusted_spec_are_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            spec_path, receipt, receipt_path = self.fixture(work)
            receipt["source_path"] = "secret"
            self.write_json(receipt_path, receipt)
            with self.assertRaises(ValueError):
                self.verify_fixture(spec_path, receipt_path)
            spec_path, receipt, receipt_path = self.fixture(work)
            receipt["recheck_tool_sha256"] = "0" * 64
            self.write_json(receipt_path, receipt)
            with self.assertRaises(ValueError):
                self.verify_fixture(spec_path, receipt_path)
            with self.assertRaises(ValueError):
                verifier.verify(receipt_path, spec_path, "0" * 64,
                                verifier.sha256_file(RECHECK), "r03-canonical-18-v2",
                                RECHECK, AUDIT)

    def test_v1_and_self_selected_recheck_tool_are_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            spec_path, receipt, receipt_path = self.fixture(work)
            receipt["receipt_version"] = "r03-canonical-21-v1"
            self.write_json(receipt_path, receipt)
            with self.assertRaises(ValueError):
                self.verify_fixture(spec_path, receipt_path,
                                    expected_version="r03-canonical-18-v2")
            alternate = os.path.join(work, "alternate_recheck.py")
            with open(alternate, "w") as stream:
                stream.write("# alternate\n")
            spec_path, receipt, receipt_path = self.fixture(work)
            receipt["recheck_tool_sha256"] = verifier.sha256_file(alternate)
            self.write_json(receipt_path, receipt)
            with self.assertRaises(ValueError):
                self.verify_fixture(spec_path, receipt_path, recheck_tool=alternate,
                                    trusted_recheck_sha256=verifier.sha256_file(RECHECK))

    def test_duplicate_receipt_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            spec_path, _receipt, receipt_path = self.fixture(work)
            with open(receipt_path, "w") as stream:
                stream.write('{"schema_version":"x","schema_version":"y"}')
            with self.assertRaises(ValueError):
                self.verify_fixture(spec_path, receipt_path)


if __name__ == "__main__":
    unittest.main()
