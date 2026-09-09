from __future__ import print_function

import csv
import os
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "data"))
import audit_phase2_manifest_recovery as audit


class Phase2ManifestRecoveryAuditTest(unittest.TestCase):
    def test_specs_cover_exactly_the_three_frozen_ids(self):
        self.assertEqual(
            {"phase2.b18.manifest", "phase2.s35932.manifest", "phase2.s38417.manifest"},
            {item["logical_id"] for item in audit.SPECS})
        self.assertEqual(4609, sum(item["rows"] for item in audit.SPECS))
        self.assertTrue(all(audit.SHA256_RE.match(item["manifest_sha256"])
                            for item in audit.SPECS))

    def test_tampered_manifest_is_rejected_before_parsing(self):
        spec = dict(audit.SPECS[0])
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "b18_attempt_manifest_v2.tsv")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                writer = csv.DictWriter(handle, fieldnames=audit.HISTORICAL_FIELDS,
                                        delimiter="\t", lineterminator="\n")
                writer.writeheader()
            spec["manifest_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                audit.audit_file(directory, spec)

    def test_receipt_builder_requires_all_three_files(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing historical manifest"):
                audit.build_receipt(directory)


if __name__ == "__main__":
    unittest.main()
