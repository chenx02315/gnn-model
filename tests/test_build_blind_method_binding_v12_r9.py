import copy
import json
import pathlib
import tempfile
import unittest

from src.data import build_blind_method_binding_v12_r9 as binding


class BuildBlindMethodBindingV12R9Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = pathlib.Path(binding.BUNDLE_ROOT)
        cls.receipt_path = cls.root / "data" / "manifests" / "blind_runtime_join_v12_r9_receipt_20260927.json"
        cls.registry_path = cls.root / "contracts" / "recommendation_method_registry_v1.json"
        cls.contract_path = cls.root / "contracts" / "blind_runtime_join_v12_r9.json"
        cls.toolchain_path = cls.root / "contracts" / "blind_method_binding_v12_r9.json"
        cls.receipt = json.loads(cls.receipt_path.read_text(encoding="utf-8"))
        cls.registry = json.loads(cls.registry_path.read_text(encoding="utf-8"))
        cls.contract = json.loads(cls.contract_path.read_text(encoding="utf-8"))
        cls.toolchain = json.loads(cls.toolchain_path.read_text(encoding="utf-8"))
        cls.contract_sha = binding.sha256_file(str(cls.contract_path))
        cls.implementation_sha = binding.implementation_set_sha256(cls.contract)

    def build(self, receipt=None, registry=None, receipt_sha=None):
        return binding.build(
            self.receipt if receipt is None else receipt,
            self.registry if registry is None else registry,
            binding.EXPECTED_RECEIPT_SHA256 if receipt_sha is None else receipt_sha,
            binding.EXPECTED_REGISTRY_SHA256,
            self.contract_sha,
            self.implementation_sha,
            self.contract,
            self.toolchain,
            binding.sha256_file(str(self.toolchain_path)),
        )

    def test_exact_receipt_bytes_and_r13_binding(self):
        self.assertEqual(binding.EXPECTED_RECEIPT_SHA256, binding.sha256_file(str(self.receipt_path)))
        result = self.build()
        self.assertEqual("PASS_R13_INDEPENDENT_AUDIT_PENDING", result["status"])
        self.assertFalse(result["training_allowed"])
        self.assertTrue(result["all_methods_identical_per_circuit"])
        for circuit in result["circuits"]:
            self.assertEqual(len(binding.EXPECTED_METHODS), len(circuit["method_bindings"]))
            self.assertEqual(
                {circuit["frozen_runtime_eligible_action_space_sha256"]},
                {row["action_space_sha256"] for row in circuit["method_bindings"]},
            )

    def test_rejects_receipt_digest_or_aggregate_drift(self):
        with self.assertRaisesRegex(ValueError, "R9_RECEIPT_DIGEST_MISMATCH"):
            self.build(receipt_sha="0" * 64)
        receipt = copy.deepcopy(self.receipt)
        receipt["circuits"][0]["eligible_action_count"] += 1
        with self.assertRaisesRegex(ValueError, "R9_AGGREGATE_DRIFT"):
            self.build(receipt=receipt)

    def test_rejects_missing_ambiguous_or_recovery_anchor_drift(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["circuits"][1]["ambiguous_runtime_join_count"] = 1
        with self.assertRaisesRegex(ValueError, "R9_R06_R07_INVALID"):
            self.build(receipt=receipt)
        receipt = copy.deepcopy(self.receipt)
        receipt["recovery_job_id"] = "forged"
        with self.assertRaisesRegex(ValueError, "R9_RECOVERY_ANCHOR_MISMATCH"):
            self.build(receipt=receipt)

    def test_rejects_method_specific_exclusion_or_method_drift(self):
        registry = copy.deepcopy(self.registry)
        registry["binding_policy"]["method_specific_exclusion_allowed"] = True
        with self.assertRaisesRegex(ValueError, "METHOD_REGISTRY_INVALID"):
            self.build(registry=registry)
        registry = copy.deepcopy(self.registry)
        registry["methods"] = registry["methods"][:-1]
        with self.assertRaisesRegex(ValueError, "METHOD_REGISTRY_INVALID"):
            self.build(registry=registry)

    def test_rejects_forged_contract_and_artifact_drift(self):
        forged = copy.deepcopy(self.contract)
        forged["status"] = "FORGED"
        with self.assertRaisesRegex(ValueError, "AUTHORIZED_R9_CONTRACT_REQUIRED"):
            binding.validate_contract(forged, self.contract_sha)
        with tempfile.TemporaryDirectory() as directory:
            fake_root = pathlib.Path(directory)
            for relative in self.contract["implementation"]["artifact_sha256"]:
                path = fake_root.joinpath(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"forged\n")
            with self.assertRaisesRegex(ValueError, "CONTRACT_ARTIFACT_DIGEST_MISMATCH"):
                binding.validate_contract(self.contract, self.contract_sha, str(fake_root))

    def test_rejects_unsealed_r13_toolchain(self):
        forged = copy.deepcopy(self.toolchain)
        forged["released_status"] = "FORGED"
        with self.assertRaisesRegex(ValueError, "R13_TOOLCHAIN_MANIFEST_INVALID"):
            binding.validate_toolchain_manifest(
                forged, binding.sha256_file(str(self.toolchain_path)), str(self.root)
            )
        forged = copy.deepcopy(self.toolchain)
        forged["lsf_or_tessent_allowed"] = True
        with self.assertRaisesRegex(ValueError, "R13_TOOLCHAIN_MANIFEST_INVALID"):
            binding.validate_toolchain_manifest(
                forged, binding.sha256_file(str(self.toolchain_path)), str(self.root)
            )

    def test_cli_writes_once_and_keeps_training_off(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "binding.json"
            rc = binding.main([
                str(self.receipt_path), str(self.registry_path), str(self.contract_path),
                str(self.toolchain_path), str(output)
            ])
            self.assertEqual(0, rc)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(result["training_allowed"])
            with self.assertRaises(FileExistsError):
                binding.main([
                    str(self.receipt_path), str(self.registry_path), str(self.contract_path),
                    str(self.toolchain_path), str(output)
                ])


if __name__ == "__main__":
    unittest.main()
