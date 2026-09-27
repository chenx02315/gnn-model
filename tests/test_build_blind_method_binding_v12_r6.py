import json
import pathlib
import unittest

from src.data import build_blind_method_binding_v12_r6 as binding


def row(circuit):
    return {"circuit": circuit, "executed_stage_reference_count": 1,
            "unique_runtime_join_count": 1, "missing_runtime_join_count": 0,
            "ambiguous_runtime_join_count": 0, "coverage_rate": 1.0,
            "distinct_runtime_attempt_count": 1, "cross_stage_reference_count": 0,
            "eligible_action_count": 1, "all_unique_action_count": 1,
            "frozen_runtime_eligible_action_space_sha256": "a" * 64,
            "source_artifact_set_sha256": "b" * 64}


class BuildBlindMethodBindingV12R6Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract_path = pathlib.Path(binding.BUNDLE_ROOT) / "contracts" / "blind_runtime_join_v12_r6.json"
        cls.contract = json.loads(cls.contract_path.read_text(encoding="utf-8"))
        cls.contract_sha = binding.sha256_file(str(cls.contract_path))
        cls.implementation_sha = binding.implementation_set_sha256(cls.contract)

    def valid_receipt(self):
        return {"schema_version": "blind-runtime-join-receipt-v12-r6",
                "status": "PASS_R06_R07_AUDIT_PENDING", "training_allowed": False,
                "method_registry_sha256": binding.EXPECTED_REGISTRY_SHA256,
                "contract_sha256": "c" * 64, "implementation_set_sha256": "d" * 64,
                "formal_runtime_membership_sha256": binding.EXPECTED_FORMAL_MEMBERSHIP_SHA256,
                "split_contract_sha256": binding.EXPECTED_SPLIT_SHA256,
                "circuits": [row(c) for c in binding.EXPECTED_CIRCUITS]}

    def test_rejects_old_receipt_schema(self):
        with self.assertRaisesRegex(ValueError, "R6_RECEIPT_REQUIRED"):
            binding.build({"schema_version": "blind-runtime-join-receipt-v12-r5"}, {},
                          "a" * 64, "b" * 64, self.contract_sha, self.implementation_sha,
                          self.contract)

    def test_binds_identical_hash_to_all_methods(self):
        receipt = self.valid_receipt()
        receipt["contract_sha256"] = self.contract_sha
        receipt["implementation_set_sha256"] = self.implementation_sha
        registry = {"methods": binding.EXPECTED_METHODS, "blind_circuits": binding.EXPECTED_CIRCUITS}
        result = binding.build(receipt, registry, "e" * 64, binding.EXPECTED_REGISTRY_SHA256,
                               self.contract_sha, self.implementation_sha, self.contract)
        self.assertTrue(result["all_methods_identical_per_circuit"])
        for circuit in result["circuits"]:
            self.assertEqual(3, len(circuit["method_bindings"]))
            self.assertEqual({"a" * 64}, {x["action_space_sha256"] for x in circuit["method_bindings"]})

    def test_rejects_fabricated_digests_and_anchor_drift(self):
        receipt = self.valid_receipt()
        receipt["contract_sha256"] = self.contract_sha
        receipt["implementation_set_sha256"] = self.implementation_sha
        registry = {"methods": binding.EXPECTED_METHODS, "blind_circuits": binding.EXPECTED_CIRCUITS}
        with self.assertRaisesRegex(ValueError, "DIGEST_INVALID"):
            binding.build(receipt, registry, "not-a-digest", binding.EXPECTED_REGISTRY_SHA256,
                          self.contract_sha, self.implementation_sha, self.contract)
        receipt["contract_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "RECEIPT_IMPLEMENTATION_BINDING_MISMATCH"):
            binding.build(receipt, registry, "e" * 64, binding.EXPECTED_REGISTRY_SHA256,
                          self.contract_sha, self.implementation_sha, self.contract)

    def test_rejects_non_hex_action_hash(self):
        receipt = self.valid_receipt()
        receipt["contract_sha256"] = self.contract_sha
        receipt["implementation_set_sha256"] = self.implementation_sha
        receipt["circuits"][0]["frozen_runtime_eligible_action_space_sha256"] = "z" * 64
        registry = {"methods": binding.EXPECTED_METHODS, "blind_circuits": binding.EXPECTED_CIRCUITS}
        with self.assertRaisesRegex(ValueError, "R6_ACTION_HASH"):
            binding.build(receipt, registry, "e" * 64, binding.EXPECTED_REGISTRY_SHA256,
                          self.contract_sha, self.implementation_sha, self.contract)

    def test_rejects_forged_contract_scope(self):
        receipt = self.valid_receipt()
        forged = dict(self.contract)
        forged["status"] = "FORGED"
        with self.assertRaisesRegex(ValueError, "AUTHORIZED_R6_CONTRACT_REQUIRED"):
            binding.build(receipt, {"methods": binding.EXPECTED_METHODS,
                                    "blind_circuits": binding.EXPECTED_CIRCUITS},
                          "e" * 64, binding.EXPECTED_REGISTRY_SHA256,
                          self.contract_sha, self.implementation_sha, forged)


if __name__ == "__main__":
    unittest.main()
