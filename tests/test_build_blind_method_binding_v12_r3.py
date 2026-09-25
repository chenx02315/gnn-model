import unittest

from src.data import build_blind_method_binding_v12_r3 as binding


class BlindMethodBindingV12R3Tests(unittest.TestCase):
    def receipt(self):
        return {"schema_version": "blind-runtime-join-receipt-v12-r3",
                "status": "PASS_R06_R07_AUDIT_PENDING",
                "method_registry_sha256": binding.EXPECTED_REGISTRY_SHA256,
                "contract_sha256": "c" * 64,
                "implementation_set_sha256": "i" * 64,
                "circuits": [{"circuit": name, "eligible_action_count": 2, "all_unique_action_count": 2,
                              "executed_stage_reference_count": 3, "unique_runtime_join_count": 3,
                              "missing_runtime_join_count": 0, "ambiguous_runtime_join_count": 0,
                              "coverage_rate": 1.0, "distinct_runtime_attempt_count": 3,
                              "cross_stage_reference_count": 0,
                              "source_artifact_set_sha256": "d" * 64,
                              "frozen_runtime_eligible_action_space_sha256": char * 64}
                             for name, char in (("s9234", "a"), ("s38584", "b"), ("wb_dma", "c"))]}

    def registry(self):
        return {"methods": list(binding.EXPECTED_METHODS),
                "blind_circuits": ["s9234", "s38584", "wb_dma"]}

    def test_all_methods_receive_identical_per_circuit_hash(self):
        result = binding.build(self.receipt(), self.registry(), "d" * 64, binding.EXPECTED_REGISTRY_SHA256,
                               "c" * 64, "i" * 64)
        self.assertTrue(result["all_methods_identical_per_circuit"])
        self.assertFalse(result["training_allowed"])
        for circuit in result["circuits"]:
            self.assertEqual({circuit["frozen_runtime_eligible_action_space_sha256"]},
                             {item["action_space_sha256"] for item in circuit["method_bindings"]})

    def test_failure_receipt_and_circuit_drift_refuse(self):
        failed = self.receipt()
        failed["status"] = "FAIL"
        with self.assertRaisesRegex(ValueError, "PASS_RECEIPT_REQUIRED"):
            binding.build(failed, self.registry(), "d" * 64, binding.EXPECTED_REGISTRY_SHA256,
                          "c" * 64, "i" * 64)
        registry = self.registry()
        registry["blind_circuits"] = list(reversed(registry["blind_circuits"]))
        with self.assertRaisesRegex(ValueError, "CIRCUIT_ORDER_MISMATCH"):
            binding.build(self.receipt(), registry, "d" * 64, binding.EXPECTED_REGISTRY_SHA256,
                          "c" * 64, "i" * 64)

    def test_method_subset_registry_digest_and_bad_r07_refuse(self):
        registry = self.registry()
        registry["methods"] = registry["methods"][:1]
        with self.assertRaisesRegex(ValueError, "METHOD_REGISTRY_INVALID"):
            binding.build(self.receipt(), registry, "d" * 64, binding.EXPECTED_REGISTRY_SHA256,
                          "c" * 64, "i" * 64)
        with self.assertRaisesRegex(ValueError, "METHOD_REGISTRY_DIGEST_MISMATCH"):
            binding.build(self.receipt(), self.registry(), "d" * 64, "0" * 64,
                          "c" * 64, "i" * 64)
        receipt = self.receipt()
        receipt["circuits"][0]["missing_runtime_join_count"] = 1
        with self.assertRaisesRegex(ValueError, "R06_R07_AGGREGATE_INVALID"):
            binding.build(receipt, self.registry(), "d" * 64, binding.EXPECTED_REGISTRY_SHA256,
                          "c" * 64, "i" * 64)

    def test_receipt_implementation_binding_refuses(self):
        with self.assertRaisesRegex(ValueError, "IMPLEMENTATION_BINDING_MISMATCH"):
            binding.build(self.receipt(), self.registry(), "d" * 64, binding.EXPECTED_REGISTRY_SHA256,
                          "0" * 64, "i" * 64)


if __name__ == "__main__":
    unittest.main()
