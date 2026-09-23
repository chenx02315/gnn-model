import copy
import hashlib
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))

import build_blind_unseal_v11_failure_receipt as builder


class BlindUnsealV11FailureReceiptTest(unittest.TestCase):
    def test_every_frozen_stage_code_pair_builds_path_free_failure(self):
        design = json.loads((ROOT / builder.DESIGN_PATH).read_text(encoding="utf-8"))
        for item in design["failure_taxonomy"]:
            fixture = builder.build_synthetic_fixture(
                str(ROOT), item["stage"], item["code"],
            )
            receipt = fixture["embedded_shape_oracle_not_public_evidence"]
            self.assertTrue(builder.validate_synthetic_expected_receipt(str(ROOT), receipt))
            self.assertEqual([], receipt["circuits"])
            serialized = json.dumps(receipt, sort_keys=True).lower()
            for forbidden in ("path", "candidate", "run_id", "wall", "exception", "traceback"):
                self.assertNotIn(forbidden, serialized)

    def test_synthetic_fixture_cannot_be_mistaken_for_execution(self):
        fixture = builder.build_synthetic_fixture(
            str(ROOT), "SOURCE_INVENTORY", "INPUT_INVENTORY_DRIFT",
        )
        self.assertEqual("SYNTHETIC_ONLY_NO_EXECUTION", fixture["status"])
        self.assertFalse(fixture["execution_authorized"])
        self.assertEqual(
            "blind-runtime-unseal-v11-synthetic-failure-fixture",
            fixture["schema_version"],
        )
        self.assertNotEqual("FAIL", fixture["status"])
        self.assertTrue(
            builder.validate_synthetic_expected_receipt(
                str(ROOT), fixture["embedded_shape_oracle_not_public_evidence"]
            )
        )

    def test_mismatched_pair_digest_and_success_semantics_are_rejected(self):
        with self.assertRaises(builder.ReceiptError):
            builder.build_synthetic_fixture(str(ROOT), "SOURCE_INVENTORY", "R06_R07_FAILED")
        fixture = builder.build_synthetic_fixture(str(ROOT), "SOURCE_INVENTORY", "INPUT_INVENTORY_DRIFT")
        receipt = fixture["embedded_shape_oracle_not_public_evidence"]
        for mutate in (
            lambda value: value.update(status="PASS"),
            lambda value: value.update(circuits=[{"circuit": "partial"}]),
            lambda value: value.update(exception_text="secret"),
            lambda value: value.update(failure_code="SEALED_AUDIT_FAILED"),
        ):
            forged = copy.deepcopy(receipt)
            mutate(forged)
            with self.assertRaises(builder.ReceiptError):
                builder.validate_synthetic_expected_receipt(str(ROOT), forged)

    def test_arbitrary_v10_and_newline_digests_are_rejected(self):
        fixture = builder.build_synthetic_fixture(str(ROOT), "SOURCE_INVENTORY", "INPUT_INVENTORY_DRIFT")
        receipt = fixture["embedded_shape_oracle_not_public_evidence"]
        for contract_digest, tool_digest in (
            ("0" * 64, "f" * 64),
            ("e438c44f63b13bd85340132958c791c474da6a3a709ff5d54eba7b957bbf287a", "f5871261b5396a426022ea1c3af32c0369c58132cc788b0689ec0f81c1962848"),
            (receipt["contract_sha256"] + "\n", receipt["tool_set_sha256"]),
        ):
            forged = copy.deepcopy(receipt)
            forged["contract_sha256"] = contract_digest
            forged["tool_set_sha256"] = tool_digest
            with self.assertRaises(builder.ReceiptError):
                builder.validate_synthetic_expected_receipt(str(ROOT), forged)

    def test_no_public_receipt_builder_is_exported(self):
        self.assertFalse(hasattr(builder, "build_failure_receipt"))
        self.assertFalse(hasattr(builder, "validate_failure_receipt"))

    def test_design_digest_is_a_trust_anchor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / builder.DESIGN_PATH
            target.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / builder.DESIGN_PATH, target)
            payload = json.loads(target.read_text(encoding="utf-8"))
            payload["failure_taxonomy"][0]["code"] = "FORGED"
            target.write_text(json.dumps(payload), encoding="utf-8")
            self.assertNotEqual(builder.DESIGN_SHA256, hashlib.sha256(target.read_bytes()).hexdigest())
            with self.assertRaises(builder.ReceiptError):
                builder.build_synthetic_fixture(str(root), "SOURCE_INVENTORY", "FORGED")


if __name__ == "__main__":
    unittest.main()
