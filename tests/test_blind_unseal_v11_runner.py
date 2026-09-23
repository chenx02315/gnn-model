import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))

import run_blind_unseal_v11 as runner
import validate_blind_unseal_v11_draft as validator


class BlindUnsealV11RunnerTest(unittest.TestCase):
    def setUp(self):
        self.draft_path = ROOT / "contracts" / "blind_runtime_unseal_v11_draft.json"
        self.draft = validator.load_draft(str(ROOT), str(self.draft_path))
        self.contract = b'{"final":"nonblind-test"}\n'
        self.tools = b'{"tool-set":"nonblind-test"}\n'

    def test_cli_and_api_pre_consumption_refusal_create_zero_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = root / "would-be-output"
            with self.assertRaisesRegex(runner.Refusal, "^REFUSED_NOT_CONSUMED$"):
                runner.run_draft(str(ROOT), str(self.draft_path), str(output))
            self.assertFalse(output.exists())
            result = subprocess.run([
                sys.executable, str(ROOT / "src" / "data" / "run_blind_unseal_v11.py"),
                "--repo-root", str(ROOT), "--draft", str(self.draft_path), "--output-root", str(output),
            ], check=False, capture_output=True, text=True)
            self.assertEqual(2, result.returncode)
            self.assertEqual("BLIND_UNSEAL_V11=REFUSED_NOT_CONSUMED\n", result.stdout)
            self.assertFalse(output.exists())

    def test_all_seven_stage_codes_have_exact_path_free_failure_shape(self):
        for stage, code in validator.TAXONOMY:
            with self.subTest(stage=stage):
                fixture = runner.build_synthetic_post_consumption_failure_fixture_for_test(
                    self.draft, self.contract, self.tools, stage, code,
                )
                self.assertEqual("SYNTHETIC_ONLY_NO_EXECUTION", fixture["status"])
                self.assertFalse(fixture["execution_authorized"])
                receipt = fixture["embedded_shape_oracle_not_public_evidence"]
                self.assertTrue(validator.validate_failure_receipt(
                    self.draft, receipt, hashlib.sha256(self.contract).hexdigest(), hashlib.sha256(self.tools).hexdigest(),
                ))
                self.assertEqual([], receipt["circuits"])
                self.assertEqual(set(validator.RECEIPT_FIELDS), set(receipt))
                payload = json.dumps(receipt, sort_keys=True).lower()
                for token in ("candidate", "path", "run_identifier", "wall_time", "exception", "traceback"):
                    self.assertNotIn(token, payload)

    def test_stage_code_digest_and_sensitive_field_forgery_are_rejected(self):
        fixture = runner.build_synthetic_post_consumption_failure_fixture_for_test(
            self.draft, self.contract, self.tools, *validator.TAXONOMY[0]
        )
        receipt = fixture["embedded_shape_oracle_not_public_evidence"]
        forged = copy.deepcopy(receipt)
        forged["failure_code"] = "R06_R07_FAILED"
        with self.assertRaises(validator.DraftError):
            validator.validate_failure_receipt(self.draft, forged, receipt["contract_sha256"], receipt["tool_set_sha256"])
        for field in ("source_path", "exception_text", "traceback", "wall_time"):
            forged = copy.deepcopy(receipt)
            forged[field] = "secret"
            with self.assertRaises(validator.DraftError):
                validator.validate_failure_receipt(self.draft, forged, receipt["contract_sha256"], receipt["tool_set_sha256"])
        with self.assertRaises(runner.Refusal):
            runner.build_synthetic_post_consumption_failure_fixture_for_test(
                self.draft, self.contract, self.tools,
                "SOURCE_INVENTORY", "R06_R07_FAILED",
            )

    def test_arbitrary_v10_and_newline_bindings_cannot_pass(self):
        fixture = runner.build_synthetic_post_consumption_failure_fixture_for_test(
            self.draft, self.contract, self.tools, *validator.TAXONOMY[0]
        )
        receipt = fixture["embedded_shape_oracle_not_public_evidence"]
        for contract_digest, tool_digest in (
            ("0" * 64, "f" * 64),
            ("e438c44f63b13bd85340132958c791c474da6a3a709ff5d54eba7b957bbf287a", "f5871261b5396a426022ea1c3af32c0369c58132cc788b0689ec0f81c1962848"),
            (receipt["contract_sha256"] + "\n", receipt["tool_set_sha256"]),
        ):
            forged = copy.deepcopy(receipt)
            forged["contract_sha256"] = contract_digest
            forged["tool_set_sha256"] = tool_digest
            with self.assertRaises(validator.DraftError):
                validator.validate_failure_receipt(self.draft, forged, receipt["contract_sha256"], receipt["tool_set_sha256"])

    def test_finalization_prerequisites_are_not_inherited_from_v10(self):
        altered = copy.deepcopy(self.draft)
        altered["draft_bindings"]["independent_review_receipt"] = "v10-pass"
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "draft.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaises(validator.DraftError):
                validator.load_draft(str(ROOT), str(path))

    def test_no_bare_public_failure_receipt_builder_is_exported(self):
        self.assertFalse(hasattr(runner, "build_post_consumption_failure_for_test"))
        fixture = runner.build_synthetic_post_consumption_failure_fixture_for_test(
            self.draft, self.contract, self.tools, *validator.TAXONOMY[0]
        )
        self.assertNotEqual("FAIL", fixture["status"])
        self.assertEqual(
            "embedded_shape_oracle_not_public_evidence",
            next(key for key in fixture if key.startswith("embedded_")),
        )


if __name__ == "__main__":
    unittest.main()
