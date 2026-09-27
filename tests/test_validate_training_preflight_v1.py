import copy
import json
import pathlib
import tempfile
import unittest

from src.data import validate_training_preflight_v1 as preflight


class ValidateTrainingPreflightV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = pathlib.Path(preflight.BUNDLE_ROOT)
        cls.contract_path = cls.root / "contracts" / "training_preflight_v1.json"
        cls.contract = json.loads(cls.contract_path.read_text(encoding="utf-8"))

    def test_repository_evidence_passes_implementation_only(self):
        receipt = preflight.validate(self.contract)
        self.assertEqual("PASS_TRAINING_IMPLEMENTATION_PREFLIGHT", receipt["status"])
        self.assertTrue(receipt["r01_r14_pass"])
        self.assertTrue(receipt["family_isolated"])
        self.assertFalse(receipt["training_execution_allowed"])
        self.assertEqual("implement_and_independently_review_runtime_training_chain", receipt["allowed_next_action"])

    def test_authority_escalation_refuses(self):
        for key in ("lsf_or_tessent_allowed", "blind_candidate_rows_allowed", "training_execution_allowed"):
            forged = copy.deepcopy(self.contract)
            forged[key] = True
            with self.assertRaisesRegex(ValueError, "PREFLIGHT_AUTHORITY_INVALID"):
                preflight.validate(forged)

    def test_source_digest_and_gate_drift_refuse(self):
        forged = copy.deepcopy(self.contract)
        forged["source_sha256"]["contracts/p0_contract_v1.json"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "PREFLIGHT_SOURCE_DIGEST_MISMATCH"):
            preflight.validate(forged)
        assessment_path = self.root / "contracts" / "runtime_recovery_gate_assessment_v2.json"
        assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
        assessment["checks"]["R13"] = "BLOCKED"
        with tempfile.TemporaryDirectory() as directory:
            fake_root = pathlib.Path(directory)
            for relative in self.contract["source_sha256"]:
                target = fake_root.joinpath(*relative.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                source = self.root.joinpath(*relative.split("/"))
                target.write_bytes(source.read_bytes())
            target = fake_root / "contracts" / "runtime_recovery_gate_assessment_v2.json"
            target.write_text(json.dumps(assessment, sort_keys=True), encoding="utf-8")
            forged = copy.deepcopy(self.contract)
            forged["source_sha256"]["contracts/runtime_recovery_gate_assessment_v2.json"] = preflight.sha256_file(str(target))
            with self.assertRaisesRegex(ValueError, "R01_R14_NOT_SEALED"):
                preflight.validate(forged, str(fake_root))

    def test_split_and_objective_drift_refuse(self):
        forged = copy.deepcopy(self.contract)
        forged["roles"]["TRAIN"] = forged["roles"]["TRAIN"][:-1]
        with self.assertRaisesRegex(ValueError, "SPLIT_MEMBERSHIP_DRIFT"):
            preflight.validate(forged)
        forged = copy.deepcopy(self.contract)
        forged["objective"]["ate_cycles_are_not_runtime_labels"] = False
        with self.assertRaisesRegex(ValueError, "OBJECTIVE_INVALID"):
            preflight.validate(forged)

    def test_blind_chain_and_runtime_accounting_drift_refuse(self):
        forged = copy.deepcopy(self.contract)
        forged["source_sha256"]["data/manifests/blind_runtime_join_v12_r9_receipt_20260927.json"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "PREFLIGHT_SOURCE_DIGEST_MISMATCH"):
            preflight.validate(forged)
        forged = copy.deepcopy(self.contract)
        forged["runtime_accounting"]["failed_attempt_elapsed_is_charged"] = False
        with self.assertRaisesRegex(ValueError, "RUNTIME_ACCOUNTING_INVALID"):
            preflight.validate(forged)

    def test_cli_writes_once(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "receipt.json"
            self.assertEqual(0, preflight.main([str(self.contract_path), str(output)]))
            self.assertFalse(json.loads(output.read_text(encoding="utf-8"))["training_execution_allowed"])
            with self.assertRaises(FileExistsError):
                preflight.main([str(self.contract_path), str(output)])


if __name__ == "__main__":
    unittest.main()
