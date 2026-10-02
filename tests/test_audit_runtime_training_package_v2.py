from __future__ import print_function

import json
import tempfile
import unittest
from pathlib import Path

from src.data import audit_runtime_training_package_v2 as audit


class RuntimeTrainingPackageV2AuditSmokeTest(unittest.TestCase):
    def test_rejects_non_pending_manifest_before_reading_sources(self):
        with tempfile.TemporaryDirectory() as root:
            package = Path(root) / "package"; package.mkdir()
            (package / "runtime_training_package_manifest_v2.json").write_text(
                json.dumps({"schema_version": "runtime-training-package-v2",
                            "status": "PASS", "training_execution_allowed": False}),
                encoding="utf-8")
            class Args(object):
                package_root = str(package)
                candidate_root = cost_root = denominator_receipt = split_contract = root
                graph_root = topology_parity_receipt = output_receipt = root
            with self.assertRaisesRegex(audit.AuditError, "PACKAGE_MANIFEST_STATUS"):
                audit.audit(Args())

    def test_rejects_missing_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            class Args(object):
                package_root = candidate_root = cost_root = root
                denominator_receipt = split_contract = graph_root = root
                topology_parity_receipt = output_receipt = root
            with self.assertRaisesRegex(audit.AuditError, "JSON_MISSING_OR_LINK"):
                audit.audit(Args())


if __name__ == "__main__":
    unittest.main()
